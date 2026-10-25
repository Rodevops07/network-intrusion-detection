"""Train the hybrid ML models on the labelled captures and save them.

Usage:  python train.py [data_dir] [model_out]
Trains on mixed_train.pcap plus the per-scenario attack captures (their benign
background teaches 'normal'; their attack windows teach the families).
"""
import json
import sys
from pathlib import Path

from nids.models import HybridModel

TRAIN_SET = ["mixed_train.pcap", "s2_portscan.pcap", "s3_dos.pcap", "s4_bruteforce.pcap"]


def main():
    data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data")
    model_out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("models/hybrid.joblib")
    pcaps = [str(data_dir / p) for p in TRAIN_SET if (data_dir / p).exists()]
    if not pcaps:
        sys.exit(f"No training pcaps in {data_dir}. Run: python -m nids.traffic_gen data")

    print(f"Training hybrid model on {len(pcaps)} captures...")
    model = HybridModel()
    report = model.fit(pcaps)
    model.save(model_out)

    print(f"\nTrained on {report['n_flows']} flows. Class counts:")
    for k, v in report["class_counts"].items():
        print(f"  {k:12s} {v}")
    print("\nTop features (Random Forest importance):")
    for name, imp in report["top_features"]:
        print(f"  {name:18s} {imp:.3f}")
    macro = report["train_report"]["macro avg"]
    print(f"\nTraining macro-F1: {macro['f1-score']:.3f}  (sanity check, not a test score)")
    model_out.with_suffix(".report.json").write_text(json.dumps(report, indent=2, default=float))
    print(f"Model saved -> {model_out}")


if __name__ == "__main__":
    main()
