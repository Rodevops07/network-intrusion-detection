"""Feature extraction: turn raw packets into per-flow feature rows.

A *flow* is one conversation between two endpoints on a transport protocol,
keyed by (src_ip, dst_ip, src_port, dst_port, proto). For each flow we compute
statistics a security analyst reasons about - rates, durations, packet/byte
counts, TCP flag mix, how many distinct ports/hosts the source touched, and so
on. These rows feed both the rule engine and the ML models.

We also keep lightweight per-source aggregates over short time windows, because
scans and floods are visible at the *source* level (one host fanning out to
many ports/targets) more than inside any single flow.
"""
from collections import defaultdict

import numpy as np
import pandas as pd
from scapy.all import ARP, ICMP, IP, TCP, UDP, PcapReader

# order of TCP flag columns we expose as features
FLAGS = ["F", "S", "R", "P", "A", "U"]
FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}


def _flag_counts(flag_int):
    return {f"flag_{f}": int(bool(flag_int & FLAG_BITS[f])) for f in FLAGS}


class FlowState:
    """Accumulates packets belonging to one flow."""
    __slots__ = ("key", "src", "dst", "sport", "dport", "proto", "first", "last",
                 "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "flags",
                 "iats", "_prev", "syn", "synack", "rst", "fin")

    def __init__(self, key):
        self.key = key
        self.src, self.dst, self.sport, self.dport, self.proto = key
        self.first = self.last = None
        self.fwd_pkts = self.bwd_pkts = 0
        self.fwd_bytes = self.bwd_bytes = 0
        self.flags = defaultdict(int)
        self.iats = []
        self._prev = None
        self.syn = self.synack = self.rst = self.fin = 0

    def update(self, t, length, is_fwd, flag_int):
        if self.first is None:
            self.first = t
        else:
            self.iats.append(t - self._prev)
        self._prev = t
        self.last = t
        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_bytes += length
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += length
        if flag_int is not None:
            for f in FLAGS:
                if flag_int & FLAG_BITS[f]:
                    self.flags[f] += 1
            syn, ack, rst, fin = flag_int & 0x02, flag_int & 0x10, flag_int & 0x04, flag_int & 0x01
            if syn and not ack:
                self.syn += 1
            elif syn and ack:
                self.synack += 1
            if rst:
                self.rst += 1
            if fin:
                self.fin += 1

    def row(self):
        dur = (self.last - self.first) if self.last and self.first else 0.0
        tot_pkts = self.fwd_pkts + self.bwd_pkts
        tot_bytes = self.fwd_bytes + self.bwd_bytes
        iats = np.array(self.iats) if self.iats else np.array([0.0])
        row = {
            "src": self.src, "dst": self.dst, "sport": self.sport,
            "dport": self.dport, "proto": self.proto,
            "start": round(self.first, 6), "end": round(self.last, 6),
            "duration": round(dur, 6),
            "tot_pkts": tot_pkts, "tot_bytes": tot_bytes,
            "fwd_pkts": self.fwd_pkts, "bwd_pkts": self.bwd_pkts,
            "fwd_bytes": self.fwd_bytes, "bwd_bytes": self.bwd_bytes,
            "pkts_per_s": tot_pkts / dur if dur > 0 else tot_pkts,
            "bytes_per_s": tot_bytes / dur if dur > 0 else tot_bytes,
            "mean_pkt_size": tot_bytes / tot_pkts if tot_pkts else 0,
            "down_up_ratio": self.bwd_pkts / self.fwd_pkts if self.fwd_pkts else 0,
            "mean_iat": float(iats.mean()), "std_iat": float(iats.std()),
            "min_iat": float(iats.min()), "max_iat": float(iats.max()),
            "syn_cnt": self.syn, "synack_cnt": self.synack,
            "rst_cnt": self.rst, "fin_cnt": self.fin,
            # true only if the initiator sent more than the opening SYN, i.e. it
            # actually completed the handshake (SYN -> SYN/ACK -> ACK + data).
            # A spoofed-source flood never does this: fwd_pkts stays at 1.
            "handshake_ok": int(self.synack > 0 and self.fwd_pkts >= 2),
            "syn_no_reply": int(self.syn > 0 and self.synack == 0 and self.bwd_pkts == 0),
        }
        for f in FLAGS:
            row[f"flag_{f}_cnt"] = self.flags.get(f, 0)
        return row


def extract_flows(pcap_path, flow_timeout=15.0):
    """Stream a pcap and return a DataFrame of per-flow feature rows.

    Bidirectional flows are canonicalised so forward = the side that sent the
    first packet (the initiator). ARP is handled separately and surfaced as a
    small set of rows describing claimed IP->MAC bindings.
    """
    flows = {}
    arp_claims = defaultdict(set)   # ip -> {macs that claimed it}
    arp_reply_src = defaultdict(int)  # mac -> count of gratuitous/unsolicited replies
    t0 = None

    for pkt in PcapReader(str(pcap_path)):
        t = float(pkt.time)
        if t0 is None:
            t0 = t

        if ARP in pkt:
            a = pkt[ARP]
            if a.op == 2:  # is-at reply
                arp_claims[a.psrc].add(a.hwsrc)
                arp_reply_src[a.hwsrc] += 1
            continue

        if IP not in pkt:
            continue
        ip = pkt[IP]
        length = len(pkt)
        if TCP in pkt:
            proto, l4 = "TCP", pkt[TCP]
            sport, dport, flag_int = int(l4.sport), int(l4.dport), int(l4.flags)
        elif UDP in pkt:
            proto, l4 = "UDP", pkt[UDP]
            sport, dport, flag_int = int(l4.sport), int(l4.dport), None
        elif ICMP in pkt:
            proto, sport, dport, flag_int = "ICMP", 0, 0, None
        else:
            proto, sport, dport, flag_int = "OTHER", 0, 0, None

        fwd_key = (ip.src, ip.dst, sport, dport, proto)
        bwd_key = (ip.dst, ip.src, dport, sport, proto)
        if fwd_key in flows and t - flows[fwd_key].last <= flow_timeout:
            flows[fwd_key].update(t, length, True, flag_int)
        elif bwd_key in flows and t - flows[bwd_key].last <= flow_timeout:
            flows[bwd_key].update(t, length, False, flag_int)
        else:
            fs = FlowState(fwd_key)
            fs.update(t, length, True, flag_int)
            flows[fwd_key] = fs

    rows = [f.row() for f in flows.values()]
    df = pd.DataFrame(rows)
    if df.empty:
        return df, pd.DataFrame(), {"t0": t0 or 0}

    df["start_rel"] = df["start"] - t0
    df["end_rel"] = df["end"] - t0
    df = df.sort_values("start").reset_index(drop=True)

    arp_df = pd.DataFrame(
        [{"ip": ip, "n_macs": len(macs), "macs": sorted(macs),
          "conflict": int(len(macs) > 1)} for ip, macs in arp_claims.items()])
    meta = {"t0": t0, "arp_reply_counts": dict(arp_reply_src)}
    return df, arp_df, meta


def add_source_window_features(df, window=10.0):
    """Per-source behaviour over sliding windows: how many distinct ports/dsts
    a source touches, and its SYN rate. This is what exposes scans and floods.
    """
    if df.empty:
        return df
    df = df.sort_values("start").reset_index(drop=True)
    starts = df["start"].values
    out = {k: np.zeros(len(df)) for k in
           ["win_dst_ports", "win_dst_hosts", "win_flows", "win_syns", "win_syn_no_reply"]}
    by_src = defaultdict(list)
    for i, src in enumerate(df["src"].values):
        by_src[src].append(i)

    dports = df["dport"].values
    dsts = df["dst"].values
    syns = df["syn_cnt"].values
    snr = df["syn_no_reply"].values
    for src, idxs in by_src.items():
        idxs = np.array(idxs)
        s = starts[idxs]
        for pos, i in enumerate(idxs):
            lo = starts[i] - window
            m = idxs[(s >= lo) & (s <= starts[i])]
            out["win_dst_ports"][i] = len(set(dports[m]))
            out["win_dst_hosts"][i] = len(set(dsts[m]))
            out["win_flows"][i] = len(m)
            out["win_syns"][i] = syns[m].sum()
            out["win_syn_no_reply"][i] = snr[m].sum()
    for k, v in out.items():
        df[k] = v
    return df


# columns the ML models consume (pure numeric behavioural features, no identities)
ML_FEATURES = [
    "duration", "tot_pkts", "tot_bytes", "fwd_pkts", "bwd_pkts",
    "fwd_bytes", "bwd_bytes", "pkts_per_s", "bytes_per_s", "mean_pkt_size",
    "down_up_ratio", "mean_iat", "std_iat", "min_iat", "max_iat",
    "syn_cnt", "synack_cnt", "rst_cnt", "fin_cnt", "handshake_ok", "syn_no_reply",
    "flag_S_cnt", "flag_A_cnt", "flag_R_cnt", "flag_F_cnt", "flag_P_cnt",
    "win_dst_ports", "win_dst_hosts", "win_flows", "win_syns", "win_syn_no_reply",
]


def build_feature_frame(pcap_path, window=10.0):
    """Full pipeline: pcap -> flow rows + source-window features + ARP table."""
    df, arp_df, meta = extract_flows(pcap_path)
    df = add_source_window_features(df, window=window)
    return df, arp_df, meta
