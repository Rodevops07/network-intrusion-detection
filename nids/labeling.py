"""Map each extracted flow to its ground-truth label using the pcap's sidecar
``.labels.json``. Used only for training the supervised model and for scoring
detection performance - the live detector never sees these labels.
"""
import json
from pathlib import Path


def load_truth(pcap_path):
    p = Path(pcap_path).with_suffix(".labels.json")
    if not p.exists():
        return None
    return json.loads(p.read_text())


def label_flows(df, truth):
    """Return a Series of labels ('benign' or the attack name) for each flow row.

    A flow is attributed to an attack when its source is one of the attack's
    sources, its destination matches, and it overlaps the attack time window.
    ARP spoofing is a layer-2 event with no IP flow, so it is scored separately.
    """
    labels = ["benign"] * len(df)
    if df is None or df.empty or truth is None:
        return labels
    t0 = 0.0
    # labels.json times are relative to capture start already (start/end fields)
    for atk in truth.get("attacks", []):
        name = atk["attack"]
        if name == "arp_spoof":
            continue  # not an IP flow; handled at L2
        srcs = set(atk["srcs"])
        dst = atk["dst"]
        start, end = atk["start"], atk["end"]
        for i, row in df.iterrows():
            if labels[i] != "benign":
                continue
            if row["src"] in srcs and row["dst"] == dst and \
               row["start_rel"] <= end + 2 and row["end_rel"] >= start - 2:
                labels[i] = name
    return labels


# normalise the various attack names into the family used for reporting
FAMILY = {
    "portscan": "portscan", "portscan_slow": "portscan",
    "dos_synflood": "dos", "ssh_bruteforce": "bruteforce",
    "benign": "benign",
}


def to_family(label):
    return FAMILY.get(label, label)
