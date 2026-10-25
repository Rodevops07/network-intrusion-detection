"""Synthetic traffic generator (offline pcap synthesis).

This module never transmits anything on a real network. It constructs Scapy
packet *objects* in memory and serialises them to ``.pcap`` files, exactly the
way public research datasets (CICIDS2017, NSL-KDD, UNSW-NB15) were produced in
a controlled lab. The pcaps give our detector a labelled mixture of benign and
malicious flows to be trained and evaluated against.

Each pcap gets a sidecar ``.labels.json`` with the ground truth (which source
attacked which destination, and when), used later to score the detector.

The malicious flow shapes mirror well-known tools so the exercise is realistic:
  * port scan       -> nmap -sS (TCP SYN scan)
  * SYN flood (DoS) -> hping3 --flood -S with spoofed sources
  * SSH brute-force -> hydra / medusa (many short, failed SSH logins)
  * ARP spoofing    -> arpspoof / ettercap (forged "gateway is-at" replies)
  * slow scan       -> nmap -T0 "paranoid" timing (scenario 5, meant to evade)
"""
import json
import random
from pathlib import Path

from scapy.all import (ARP, ICMP, IP, TCP, UDP, DNS, DNSQR, DNSRR, Ether, Raw,
                       wrpcap)

# ---------------------------------------------------------------- topology
SUBNET = "10.0.0."
GATEWAY_IP = "10.0.0.1"
DNS_IP = "10.0.0.2"
MONITOR_IP = "10.0.0.5"
WEB_IP = "10.0.0.10"
SSH_IP = "10.0.0.20"
ATTACKER_IP = "10.0.0.66"
CLIENTS = [f"10.0.0.{i}" for i in range(101, 121)]
ADMINS = CLIENTS[:2]  # these two users legitimately SSH into the servers
EXTERNAL = ["93.184.216.34", "142.250.183.14", "151.101.1.69", "104.16.132.229",
            "13.107.42.14", "157.240.16.35", "52.95.120.38", "185.199.108.153"]
OPEN_PORTS = {WEB_IP: {22, 80, 443}, SSH_IP: {22}}


def mac_of(ip):
    """Deterministic MAC for every simulated host (02:.. = locally administered)."""
    a, b, c, d = (int(x) for x in ip.split("."))
    return f"02:00:{a:02x}:{b:02x}:{c:02x}:{d:02x}"


def _local(ip):
    return ip.startswith(SUBNET)


class Capture:
    """Collects timestamped packets plus the ground-truth records for one pcap."""

    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.pkts = []
        self.labels = []
        self.floods = []  # (target, start, end): server degraded while flooded

    # -- low-level helpers -------------------------------------------------
    def add(self, t, pkt):
        pkt.time = round(t, 6)
        self.pkts.append(pkt)

    def ether(self, src, dst):
        # Off-subnet traffic goes via the gateway's MAC, like a real LAN.
        dst_mac = mac_of(dst) if _local(dst) else mac_of(GATEWAY_IP)
        src_mac = mac_of(src) if _local(src) else mac_of(GATEWAY_IP)
        return Ether(src=src_mac, dst=dst_mac)

    def ip(self, src, dst):
        return self.ether(src, dst) / IP(src=src, dst=dst, ttl=64 if _local(src) else 52)

    def label(self, attack, srcs, dst, start, end, **extra):
        self.labels.append({"attack": attack, "srcs": list(srcs), "dst": dst,
                            "start": round(start, 3), "end": round(end, 3), **extra})

    def server_state(self, server, t):
        """(drop_probability, extra_delay) for a server, worse while it is flooded."""
        for target, s, e in self.floods:
            if target == server and s <= t <= e:
                return 0.65, self.rng.uniform(0.3, 1.2)
        return 0.0, 0.0

    # -- benign building blocks --------------------------------------------
    def tcp_session(self, c, s, dport, t, req=300, resp=4000, rtt=None):
        """One full TCP connection: handshake, request/response, graceful close."""
        rng = self.rng
        rtt = rtt or (rng.uniform(0.0005, 0.003) if _local(s) else rng.uniform(0.015, 0.08))
        sport = rng.randint(32768, 60999)
        cseq, sseq = rng.getrandbits(32), rng.getrandbits(32)

        # Handshake, with SYN retransmissions if the server is overloaded.
        for attempt in range(3):
            self.add(t, self.ip(c, s) / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
            drop, delay = self.server_state(s, t)
            if rng.random() >= drop:
                t += delay
                break
            t += 1.0 * (2 ** attempt)  # client SYN retransmit timer (1s, 2s, 4s)
        else:
            return t  # gave up: connection failed (service effectively denied)

        self.add(t + rtt / 2, self.ip(s, c) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
        t += rtt
        self.add(t, self.ip(c, s) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
        cseq += 1
        sseq += 1

        t += rng.uniform(0.0005, 0.01)
        self.add(t, self.ip(c, s) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(b"q" * req))
        cseq += req
        t += rtt / 2 + rng.uniform(0.001, 0.02)  # server think time
        sent = 0
        while sent < resp:
            seg = min(1400, resp - sent)
            self.add(t, self.ip(s, c) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(b"r" * seg))
            sseq += seg
            sent += seg
            t += rng.uniform(0.0002, 0.002)
            if sent % 2800 == 0 or sent >= resp:
                self.add(t + rtt / 2, self.ip(c, s) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        t += rtt
        self.add(t, self.ip(c, s) / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
        self.add(t + rtt / 2, self.ip(s, c) / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
        self.add(t + rtt, self.ip(c, s) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
        return t + rtt

    def dns_lookup(self, c, t):
        name = self.rng.choice(["example.com", "google.com", "github.com", "cdn.jsdelivr.net",
                                "login.microsoftonline.com", "api.slack.com", "updates.apple.com"])
        sport, qid = self.rng.randint(32768, 60999), self.rng.getrandbits(16)
        self.add(t, self.ip(c, DNS_IP) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
        t += self.rng.uniform(0.002, 0.03)
        self.add(t, self.ip(DNS_IP, c) / UDP(sport=53, dport=sport) /
                 DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name),
                     an=DNSRR(rrname=name, rdata=self.rng.choice(EXTERNAL))))
        return t

    def ping(self, c, dst, t, count=3):
        for i in range(count):
            self.add(t, self.ip(c, dst) / ICMP(type=8, id=7, seq=i) / Raw(b"p" * 56))
            self.add(t + 0.002, self.ip(dst, c) / ICMP(type=0, id=7, seq=i) / Raw(b"p" * 56))
            t += 1.0
        return t

    def arp_exchange(self, c, t):
        """Client resolves the gateway's MAC; the real gateway answers (benign)."""
        self.add(t, Ether(src=mac_of(c), dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=1, hwsrc=mac_of(c), psrc=c, pdst=GATEWAY_IP))
        self.add(t + 0.0005, Ether(src=mac_of(GATEWAY_IP), dst=mac_of(c)) /
                 ARP(op=2, hwsrc=mac_of(GATEWAY_IP), psrc=GATEWAY_IP, hwdst=mac_of(c), pdst=c))

    def admin_ssh(self, c, s, t):
        """Legitimate interactive SSH session: one long connection, many small packets."""
        return self.tcp_session(c, s, 22, t, req=self.rng.randint(800, 3000),
                                resp=self.rng.randint(5000, 40000))

    # -- background traffic ------------------------------------------------
    def normal_background(self, duration, t0=0.0, user_rate=1 / 8):
        """Each client performs Poisson-distributed 'user actions'."""
        rng = self.rng
        for c in CLIENTS:
            self.arp_exchange(c, t0 + rng.uniform(0, 2))
            t = t0 + rng.expovariate(user_rate)
            next_arp = t0 + rng.uniform(40, 90)
            while t < t0 + duration:
                if t > next_arp:  # periodic ARP cache refresh
                    self.arp_exchange(c, t)
                    next_arp = t + rng.uniform(40, 90)
                r = rng.random()
                if r < 0.55:  # browse the web: DNS + 1-3 HTTPS connections
                    t2 = self.dns_lookup(c, t)
                    dst = rng.choice(EXTERNAL)
                    for _ in range(rng.randint(1, 3)):
                        self.tcp_session(c, dst, rng.choice([443, 443, 443, 80]), t2 + rng.uniform(0, 0.3),
                                         req=rng.randint(200, 900), resp=rng.randint(2000, 60000))
                elif r < 0.80:  # internal web application
                    self.tcp_session(c, WEB_IP, rng.choice([80, 443]), t,
                                     req=rng.randint(200, 1200), resp=rng.randint(1500, 20000))
                elif r < 0.92:
                    self.dns_lookup(c, t)
                elif r < 0.96:
                    self.ping(c, rng.choice([GATEWAY_IP, WEB_IP, DNS_IP]), t, count=rng.randint(1, 4))
                elif c in ADMINS:
                    self.admin_ssh(c, rng.choice([SSH_IP, WEB_IP]), t)
                t += rng.expovariate(user_rate)

    def network_monitor(self, duration, t0=0.0, every=60):
        """Benign monitoring host (Nagios-style) checking service ports.

        Included deliberately: its periodic port checks look a little scan-like,
        which is a realistic source of false positives for our detector.
        """
        targets = [(WEB_IP, [22, 80, 443, 3306, 8080]), (SSH_IP, [22, 2222]), (DNS_IP, [53, 853])]
        t = t0 + 5
        while t < t0 + duration:
            for host, ports in targets:
                for p in ports:
                    if p in OPEN_PORTS.get(host, set()):
                        self.tcp_session(MONITOR_IP, host, p, t, req=60, resp=200)
                    else:
                        self._probe(MONITOR_IP, host, p, t)
                    t += 0.05
            t += every

    # -- malicious flow shapes (still pure offline pcap synthesis) ----------
    def _probe(self, a, s, port, t):
        """One SYN probe -> open port answers SYN/ACK then RST; closed -> RST/ACK."""
        sport = self.rng.randint(40000, 65000)
        seq = self.rng.getrandbits(32)
        self.add(t, self.ip(a, s) / TCP(sport=sport, dport=port, flags="S", seq=seq, window=1024))
        rtt = self.rng.uniform(0.0004, 0.002)
        if port in OPEN_PORTS.get(s, set()):
            self.add(t + rtt / 2, self.ip(s, a) / TCP(sport=port, dport=sport, flags="SA", ack=seq + 1))
            self.add(t + rtt, self.ip(a, s) / TCP(sport=sport, dport=port, flags="R", seq=seq + 1))
        else:
            self.add(t + rtt / 2, self.ip(s, a) / TCP(sport=port, dport=sport, flags="RA", ack=seq + 1))

    def port_scan(self, target, ports, t0, gap, attacker=ATTACKER_IP, attack="portscan"):
        """SYN scan: many short probes to many ports from one source (nmap -sS)."""
        ports = list(ports)
        self.rng.shuffle(ports)  # nmap randomises port order
        t = t0
        for p in ports:
            self._probe(attacker, target, p, t)
            t += self.rng.uniform(gap * 0.5, gap * 1.5)
        self.label(attack, [attacker], target, t0, t, ports=len(ports))
        return t

    def syn_flood(self, target, dport, t0, duration, rate, pool_size=200):
        """Half-open flood: a burst of SYNs from spoofed sources, few completions.

        Marks the server as degraded for the window so benign connections in the
        same pcap show retransmits/failures - the measurable 'impact' DoS has.
        """
        rng = self.rng
        pool = [f"198.51.100.{i % 254 + 1}" for i in range(pool_size)]
        self.floods.append((target, t0, t0 + duration))
        t, n = t0, 0
        while t < t0 + duration:
            src = rng.choice(pool)
            sport, seq = rng.randint(1024, 65000), rng.getrandbits(32)
            self.add(t, self.ip(src, target) / TCP(sport=sport, dport=dport, flags="S", seq=seq, window=512))
            if rng.random() < 0.5:  # server replies SYN/ACK; spoofed src never ACKs
                self.add(t + 0.0002, self.ip(target, src) / TCP(sport=dport, dport=sport, flags="SA", ack=seq + 1))
            n += 1
            t += rng.expovariate(rate)
        self.label("dos_synflood", sorted(set(pool)), target, t0, t0 + duration, syns=n, spoofed=True)
        return t0 + duration

    def ssh_bruteforce(self, target, t0, attempts, gap, attacker=ATTACKER_IP):
        """Many short SSH connections that each fail quickly (hydra-style)."""
        rng = self.rng
        t = t0
        for _ in range(attempts):
            sport, cseq, sseq = rng.randint(40000, 65000), rng.getrandbits(32), rng.getrandbits(32)
            self.add(t, self.ip(attacker, target) / TCP(sport=sport, dport=22, flags="S", seq=cseq))
            self.add(t + 0.0008, self.ip(target, attacker) / TCP(sport=22, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
            self.add(t + 0.0012, self.ip(attacker, target) / TCP(sport=sport, dport=22, flags="A", seq=cseq + 1, ack=sseq + 1))
            # SSH banner + a short key exchange, then the server resets the login.
            self.add(t + 0.002, self.ip(target, attacker) / TCP(sport=22, dport=sport, flags="PA", seq=sseq + 1, ack=cseq + 1) / Raw(b"SSH-2.0-OpenSSH_8.9\r\n"))
            self.add(t + 0.004, self.ip(attacker, target) / TCP(sport=sport, dport=22, flags="PA", seq=cseq + 1, ack=sseq + 22) / Raw(b"SSH-2.0-paramiko\r\n" + b"x" * rng.randint(60, 120)))
            self.add(t + 0.02, self.ip(target, attacker) / TCP(sport=22, dport=sport, flags="PA", seq=sseq + 22, ack=cseq + 100) / Raw(b"x" * rng.randint(40, 90)))
            self.add(t + 0.03, self.ip(target, attacker) / TCP(sport=22, dport=sport, flags="FA", seq=sseq + 100, ack=cseq + 100))
            self.add(t + 0.031, self.ip(attacker, target) / TCP(sport=sport, dport=22, flags="FA", seq=cseq + 100, ack=sseq + 101))
            t += rng.uniform(gap * 0.6, gap * 1.4)
        self.label("ssh_bruteforce", [attacker], target, t0, t, attempts=attempts)
        return t

    def arp_spoof(self, t0, duration, every, attacker=ATTACKER_IP, victims=None):
        """Forged 'gateway is-at <attacker MAC>' replies (arpspoof / ettercap).

        The hallmark: one MAC suddenly claims an IP already bound to another MAC.
        """
        victims = victims or CLIENTS[:5]
        t = t0
        while t < t0 + duration:
            for v in victims:  # tell the victim the attacker IS the gateway
                self.add(t, Ether(src=mac_of(attacker), dst=mac_of(v)) /
                         ARP(op=2, hwsrc=mac_of(attacker), psrc=GATEWAY_IP, hwdst=mac_of(v), pdst=v))
                t += 0.01
            # also poison the gateway so the attacker sits in the middle both ways
            self.add(t, Ether(src=mac_of(attacker), dst=mac_of(GATEWAY_IP)) /
                     ARP(op=2, hwsrc=mac_of(attacker), psrc=CLIENTS[0], hwdst=mac_of(GATEWAY_IP), pdst=GATEWAY_IP))
            t += every
        self.label("arp_spoof", [attacker], GATEWAY_IP, t0, t0 + duration,
                   spoofed_ip=GATEWAY_IP, real_mac=mac_of(GATEWAY_IP), fake_mac=mac_of(attacker))
        return t0 + duration

    # -- output ------------------------------------------------------------
    def write(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.pkts.sort(key=lambda p: p.time)
        wrpcap(str(path), self.pkts)
        meta = {"pcap": path.name, "packets": len(self.pkts),
                "duration": round(self.pkts[-1].time - self.pkts[0].time, 2) if self.pkts else 0,
                "attacks": self.labels}
        path.with_suffix(".labels.json").write_text(json.dumps(meta, indent=2))
        return meta


# ---------------------------------------------------------------- scenarios
def scenario_normal(out):
    """Scenario 1 - benign baseline only (plus the noisy monitoring host)."""
    cap = Capture(seed=1)
    cap.normal_background(duration=600, user_rate=1 / 8)
    cap.network_monitor(duration=600)
    return cap.write(Path(out) / "s1_normal.pcap")


def scenario_portscan(out):
    """Scenario 2 - benign baseline + an aggressive full port scan."""
    cap = Capture(seed=2)
    cap.normal_background(duration=400, user_rate=1 / 8)
    cap.network_monitor(duration=400)
    cap.port_scan(WEB_IP, range(1, 1025), t0=180, gap=0.03)
    return cap.write(Path(out) / "s2_portscan.pcap")


def scenario_dos(out):
    """Scenario 3 - benign baseline + a SYN flood against the web server."""
    cap = Capture(seed=3)
    cap.normal_background(duration=400, user_rate=1 / 6)
    cap.network_monitor(duration=400)
    cap.syn_flood(WEB_IP, 80, t0=150, duration=60, rate=400)
    return cap.write(Path(out) / "s3_dos.pcap")


def scenario_bruteforce(out):
    """Scenario 4 - benign baseline + SSH brute-force against the SSH server."""
    cap = Capture(seed=4)
    cap.normal_background(duration=400, user_rate=1 / 8)
    cap.network_monitor(duration=400)
    cap.ssh_bruteforce(SSH_IP, t0=120, attempts=300, gap=0.4)
    return cap.write(Path(out) / "s4_bruteforce.pcap")


def scenario_mixed(out):
    """A longer capture mixing every attack - used to train/evaluate the ML model."""
    cap = Capture(seed=5)
    cap.normal_background(duration=900, user_rate=1 / 7)
    cap.network_monitor(duration=900)
    cap.port_scan(WEB_IP, range(1, 1025), t0=120, gap=0.03)
    cap.port_scan(SSH_IP, range(1, 513), t0=300, gap=0.05)
    cap.syn_flood(WEB_IP, 80, t0=450, duration=45, rate=350)
    cap.ssh_bruteforce(SSH_IP, t0=600, attempts=250, gap=0.4)
    cap.arp_spoof(t0=750, duration=60, every=5)
    return cap.write(Path(out) / "mixed_train.pcap")


def scenario_ambiguous(out):
    """Scenario 5 - a deliberately evasive 'low and slow' scan + ARP spoof.

    The slow scan spreads a few probes over minutes to stay under rate-based
    thresholds, so our rule layer is expected to miss it - the honest limitation.
    """
    cap = Capture(seed=6)
    cap.normal_background(duration=600, user_rate=1 / 8)
    cap.network_monitor(duration=600)
    # ~40 probes spread over ~8 minutes: well below the burst a scan usually makes.
    cap.port_scan(WEB_IP, [21, 22, 23, 25, 53, 110, 143, 443, 445, 993, 995, 1433,
                           1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
                           27017, 11211, 2049, 5060, 161, 389, 636, 8000, 8888,
                           9000, 10000, 3000, 4444, 5555, 7001, 8081, 9090, 50000,
                           1723], t0=60, gap=12.0, attack="portscan_slow")
    cap.arp_spoof(t0=400, duration=40, every=6)
    return cap.write(Path(out) / "s5_ambiguous.pcap")


SCENARIOS = {
    "s1_normal": scenario_normal,
    "s2_portscan": scenario_portscan,
    "s3_dos": scenario_dos,
    "s4_bruteforce": scenario_bruteforce,
    "mixed_train": scenario_mixed,
    "s5_ambiguous": scenario_ambiguous,
}


def generate_all(out="data"):
    out = Path(out)
    results = {}
    for name, fn in SCENARIOS.items():
        meta = fn(out)
        results[name] = meta
        print(f"  {name:14s} -> {meta['packets']:6d} pkts, {meta['duration']:6.1f}s, "
              f"{len(meta['attacks'])} attack(s)")
    return results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "data"
    print("Generating synthetic pcaps (offline; nothing is sent on any network)...")
    generate_all(target)
    print("Done.")
