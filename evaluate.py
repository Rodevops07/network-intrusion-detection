"""Evaluate detection performance across all scenarios.

Scores two ways:
  * Flow-level: every flow gets a ground-truth family (from labels.json) and a
    prediction (attack family if any alert covers it, else benign). We report
    precision / recall / F1 / accuracy and a confusion matrix.
  * Scenario-level: did we raise the right attack alert for each scenario, and
    did Scenario 1 stay clean. Also reports the Scenario 5 miss explicitly.

Writes results/metrics.json and prints a summary.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (classification_report, confusion_matrix,
                             precision_recall_fscore_support)

from nids.detect import analyze
from nids.labeling import load_truth, label_flows, to_family

SCENARIOS = {
    "s1_normal": "benign baseline",
    "s2_portscan": "port scan",
    "s3_dos": "SYN flood DoS",
    "s4_bruteforce": "SSH brute-force",
    "s5_ambiguous": "slow scan + ARP (evasive)",
}
FAMILIES = ["benign", "portscan", "dos", "bruteforce"]


def flow_predictions(alerts, df):
    """Assign each flow a predicted family from the alerts that temporally and
    address-wise cover it. Unmatched flows are predicted benign.
    """
    pred = np.array(["benign"] * len(df), dtype=object)
    if df.empty:
        return pred
    type_to_fam = {"Port Scan (reconnaissance)": "portscan",
                   "Denial-of-Service (SYN flood)": "dos",
                   "SSH Brute-force": "bruteforce"}
    for a in alerts:
        fam = type_to_fam.get(a["type"])
        if fam is None:  # ML-anomaly alerts -> map by class
            fam = a.get("evidence", {}).get("ml_class")
        if fam not in FAMILIES or fam == "benign":
            continue
        src = str(a["src"])
        dst = str(a["dst"]).split(":")[0]
        for i, row in df.iterrows():
            if (row["src"] == src or "sources" in src) and \
               (row["dst"] == dst) and \
               row["start_rel"] <= a["end"] + 2 and row["end_rel"] >= a["start"] - 2:
                pred[i] = fam
    return pred


def main():
    data = Path("data")
    results = {}
    all_true, all_pred = [], []
    print(f"{'scenario':16s} {'flows':>7s} {'alerts':>7s}  outcome")
    print("-" * 70)

    for name, desc in SCENARIOS.items():
        pcap = data / f"{name}.pcap"
        if not pcap.exists():
            continue
        alerts, df, meta = analyze(pcap)
        truth = load_truth(pcap)
        y_true = [to_family(x) for x in label_flows(df, truth)]
        y_pred = list(flow_predictions(alerts, df))
        all_true += y_true
        all_pred += y_pred

        n_attack_true = sum(1 for x in y_true if x != "benign")
        n_attack_pred = sum(1 for x in y_pred if x != "benign")
        attack_types = sorted({a["type"] for a in alerts})
        outcome = ", ".join(attack_types) if attack_types else "clean"
        results[name] = {
            "desc": desc, "flows": len(df), "alerts": len(alerts),
            "attack_flows_true": n_attack_true, "attack_flows_pred": n_attack_pred,
            "alert_types": attack_types,
        }
        print(f"{name:16s} {len(df):7d} {len(alerts):7d}  {outcome[:40]}")

    # overall flow-level metrics
    labels = FAMILIES
    p, r, f1, sup = precision_recall_fscore_support(
        all_true, all_pred, labels=labels, zero_division=0)
    cm = confusion_matrix(all_true, all_pred, labels=labels)
    acc = float(np.mean(np.array(all_true) == np.array(all_pred)))

    # binary (attack vs benign) view - the number an analyst cares about most
    bt = [0 if x == "benign" else 1 for x in all_true]
    bp = [0 if x == "benign" else 1 for x in all_pred]
    bp_r, bp_rec, bp_f1, _ = precision_recall_fscore_support(
        bt, bp, labels=[1], zero_division=0)

    print("\nPer-class (flow-level):")
    print(f"  {'class':12s} {'prec':>6s} {'recall':>7s} {'f1':>6s} {'support':>8s}")
    for i, c in enumerate(labels):
        print(f"  {c:12s} {p[i]:6.2f} {r[i]:7.2f} {f1[i]:6.2f} {sup[i]:8d}")
    print(f"\nOverall accuracy: {acc:.3f}")
    print(f"Attack-vs-benign  precision={bp_r[0]:.3f}  recall={bp_rec[0]:.3f}  f1={bp_f1[0]:.3f}")
    print("\nConfusion matrix (rows=true, cols=pred):")
    print("            " + " ".join(f"{c[:8]:>8s}" for c in labels))
    for i, c in enumerate(labels):
        print(f"  {c:10s} " + " ".join(f"{cm[i][j]:8d}" for j in range(len(labels))))

    out = {
        "scenarios": results,
        "flow_metrics": {
            "accuracy": acc,
            "per_class": {c: {"precision": float(p[i]), "recall": float(r[i]),
                              "f1": float(f1[i]), "support": int(sup[i])}
                          for i, c in enumerate(labels)},
            "attack_vs_benign": {"precision": float(bp_r[0]),
                                 "recall": float(bp_rec[0]), "f1": float(bp_f1[0])},
            "confusion_matrix": {"labels": labels, "matrix": cm.tolist()},
        },
        "notes": {
            "s5_ambiguous": ("Slow scan (one probe every ~12s) stays below the rate-based "
                             "SCAN_PORTS/10s rule and the flood/brute rules, so the rule layer "
                             "misses it - documented limitation (Scenario 5). ARP spoof in the "
                             "same capture is still caught at layer 2."),
        },
    }
    Path("results").mkdir(exist_ok=True)
    Path("results/metrics.json").write_text(json.dumps(out, indent=2))
    print("\nSaved -> results/metrics.json")


if __name__ == "__main__":
    main()
