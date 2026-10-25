"""Signature / rule-based detection layer.

Fast, transparent heuristics that catch the textbook shape of each attack. Every
hit carries a human-readable reason, the evidence (the numbers that tripped it),
and a severity - so an analyst sees *why*, not just *what*. These rules are the
signature half of the hybrid; the ML layer (anomaly.py / classifier) is the
behavioural half that catches what fixed thresholds miss.

Thresholds are documented inline and are intentionally conservative, tuned on
the benign baseline so the noisy monitoring host does not trip them.
"""
from collections import defaultdict

# ---- tunable thresholds (documented; see technical report for justification)
SCAN_PORTS = 50          # distinct dst ports from one src within the window
SCAN_WINDOW_FLOWS = 40   # flows from one src within the window
DOS_SYN_RATE = 150       # SYNs/sec toward one dst:port with few completions
DOS_MIN_SYNS = 300
BRUTE_ATTEMPTS = 20      # short connections to dst:22 from one src
BRUTE_WINDOW = 60.0


def _sev(score):
    return "critical" if score >= 0.9 else "high" if score >= 0.7 else \
           "medium" if score >= 0.4 else "low"


def detect_port_scan(df):
    """One source hitting many distinct ports in a short window = scan.

    Keyed off the precomputed source-window features. Benign monitoring touches
    only a handful of known ports, so it stays below SCAN_PORTS.
    """
    events = []
    if df.empty:
        return events
    scan = df[df["win_dst_ports"] >= SCAN_PORTS]
    for (src, dst), g in scan.groupby(["src", "dst"]):
        peak = int(g["win_dst_ports"].max())
        ratio_closed = float((g["syn_no_reply"].sum() + g["rst_cnt"].sum()) / max(len(g), 1))
        score = min(1.0, peak / 300)
        events.append({
            "type": "Port Scan (reconnaissance)", "src": src, "dst": dst,
            "start": float(g["start_rel"].min()), "end": float(g["end_rel"].max()),
            "severity": _sev(score), "confidence": round(0.6 + 0.4 * score, 2),
            "reason": (f"Source {src} probed {peak} distinct ports on {dst} within a "
                       f"10s window (threshold {SCAN_PORTS}); many probes got RST/no reply, "
                       f"the signature of a TCP SYN scan (nmap -sS)."),
            "evidence": {"distinct_ports_peak": peak, "flows": int(len(g)),
                         "closed_or_unanswered_ratio": round(ratio_closed, 2)},
            "rule": "SCAN_PORTS>=%d/10s" % SCAN_PORTS,
        })
    return events


DOS_BIN = 5.0  # seconds; peak SYN rate is measured over this window, not the
               # whole capture, so a short flood burst is not averaged away.


def detect_dos(df):
    """High rate of SYNs to one dst:port with few completed handshakes = SYN flood.

    The rate is the *peak* over a short (DOS_BIN) window, so a 60s flood inside a
    400s capture is not diluted by the surrounding benign traffic.
    """
    import numpy as np
    events = []
    if df.empty:
        return events
    tcp = df[df["proto"] == "TCP"]
    for (dst, dport), g in tcp.groupby(["dst", "dport"]):
        syns = int(g["syn_cnt"].sum())
        if syns < DOS_MIN_SYNS:
            continue
        # bin SYNs by start time and find the busiest window
        bins = (g["start_rel"] // DOS_BIN).astype(int)
        syn_per_bin = g.groupby(bins)["syn_cnt"].sum()
        peak_bin = int(syn_per_bin.idxmax())
        peak_syns = int(syn_per_bin.max())
        peak_rate = peak_syns / DOS_BIN
        in_peak = g[bins == peak_bin]
        completion = int(in_peak["handshake_ok"].sum()) / max(int(in_peak["syn_cnt"].sum()), 1)
        if peak_rate >= DOS_SYN_RATE and completion < 0.2:
            score = min(1.0, peak_rate / 800)
            srcs = in_peak["src"].nunique()
            b_start = peak_bin * DOS_BIN
            # extend window across contiguous busy bins for a readable time range
            busy = sorted(int(b) for b, v in syn_per_bin.items() if v / DOS_BIN >= DOS_SYN_RATE / 2)
            w_start = busy[0] * DOS_BIN if busy else b_start
            w_end = (busy[-1] + 1) * DOS_BIN if busy else b_start + DOS_BIN
            events.append({
                "type": "Denial-of-Service (SYN flood)", "src": f"{srcs} sources",
                "dst": f"{dst}:{dport}",
                "start": float(w_start), "end": float(w_end),
                "severity": _sev(max(score, 0.8)), "confidence": round(0.7 + 0.3 * score, 2),
                "reason": (f"{syns} SYNs hit {dst}:{dport}, peaking at ~{peak_rate:.0f}/s from "
                           f"{srcs} sources, with only {completion*100:.0f}% completing the "
                           f"handshake - a half-open SYN flood exhausting the connection table."),
                "evidence": {"syn_count": syns, "peak_syn_rate_per_s": round(peak_rate, 1),
                             "handshake_completion_in_peak": round(completion, 3),
                             "distinct_sources_in_peak": srcs},
                "rule": "PEAK_SYN_RATE>=%d/s & completion<20%%" % DOS_SYN_RATE,
            })
    return events


def detect_bruteforce(df):
    """Many short SSH connections from one source in a window = credential brute-force."""
    events = []
    if df.empty:
        return events
    ssh = df[(df["dport"] == 22) & (df["proto"] == "TCP")].copy()
    for (src, dst), g in ssh.groupby(["src", "dst"]):
        g = g.sort_values("start_rel")
        times = g["start_rel"].values
        best = 0
        for i in range(len(times)):
            window = times[(times >= times[i]) & (times <= times[i] + BRUTE_WINDOW)]
            best = max(best, len(window))
        if best >= BRUTE_ATTEMPTS:
            short = g[g["tot_pkts"] <= 12]
            score = min(1.0, best / 200)
            events.append({
                "type": "SSH Brute-force", "src": src, "dst": f"{dst}:22",
                "start": float(g["start_rel"].min()), "end": float(g["end_rel"].max()),
                "severity": _sev(max(score, 0.6)), "confidence": round(0.65 + 0.35 * score, 2),
                "reason": (f"Source {src} opened {best} SSH connections to {dst} within "
                           f"{BRUTE_WINDOW:.0f}s ({len(short)} were short/aborted logins) - "
                           f"consistent with automated password guessing (hydra-style)."),
                "evidence": {"connections_in_window": int(best),
                             "short_connections": int(len(short)),
                             "total_ssh_flows": int(len(g))},
                "rule": "SSH_CONNS>=%d/%ds" % (BRUTE_ATTEMPTS, BRUTE_WINDOW),
            })
    return events


def detect_arp_spoof(arp_df, meta):
    """Two different MACs claiming the same IP = ARP cache poisoning / MITM."""
    events = []
    if arp_df is None or arp_df.empty:
        return events
    for _, r in arp_df[arp_df["conflict"] == 1].iterrows():
        events.append({
            "type": "ARP Spoofing (MITM)", "src": ", ".join(r["macs"]), "dst": r["ip"],
            "start": 0.0, "end": 0.0, "severity": "critical", "confidence": 0.9,
            "reason": (f"IP {r['ip']} was claimed by {r['n_macs']} different MAC addresses "
                       f"({', '.join(r['macs'])}). A gateway/host IP mapping to multiple MACs "
                       f"indicates ARP cache poisoning - an attacker inserting itself as MITM."),
            "evidence": {"ip": r["ip"], "macs": r["macs"], "n_macs": int(r["n_macs"])},
            "rule": "ARP_IP_MULTIPLE_MACS",
        })
    return events


def run_rules(df, arp_df, meta):
    """Run every rule and return a flat list of alert dicts."""
    events = []
    events += detect_port_scan(df)
    events += detect_dos(df)
    events += detect_bruteforce(df)
    events += detect_arp_spoof(arp_df, meta)
    for e in events:
        e["layer"] = "rule"
    return events
