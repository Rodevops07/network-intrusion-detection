"""Hybrid detector: combine the rule layer and the ML layer into one verdict.

Pipeline for a pcap:
  1. extract per-flow features (features.py)
  2. run the signature/rule layer (rules.py)
  3. run the ML layer (models.py): anomaly score + attack-family classification
  4. fuse: rules give precise, explainable hits; ML adds anomaly-backed flags for
     behaviour the rules missed, and raises confidence when both agree.

Returns a list of alert dicts, each with what/why/evidence/severity/confidence,
plus a per-flow frame for the dashboard and evaluation.
"""
from pathlib import Path

import numpy as np
import pandas as pd

from .features import build_feature_frame
from .models import HybridModel
from .rules import run_rules

# how anomalous an ML-only flag must be to surface as its own alert
ANOMALY_ALERT = 0.15
ANOMALY_MIN_FLOWS = 5


def _ml_group_alerts(df, meta):
    """Surface ML-only detections: clusters of anomalous flows the rules missed.

    Grouped by (src, predicted-class) so we report 'host X shows N anomalous
    dos-like flows' rather than one alert per packet burst.

    We only raise an alert when the Isolation Forest says 'outlier' AND the
    Random Forest names an *attack* family. Flows the classifier still calls
    benign (big downloads, the monitoring host) are outliers in distance but
    not threats; raising them would flood Scenario 1 with false positives. We
    count them into meta['suppressed_benign_anomalies'] for an honest FP story.
    """
    events = []
    if df.empty or "is_anomaly" not in df:
        return events
    anom = df[(df["is_anomaly"] == 1) & (df["anomaly_score"] >= ANOMALY_ALERT)]
    attack_label = {"dos": "DoS-like", "portscan": "Scan-like",
                    "bruteforce": "Brute-force-like"}
    suppressed = 0
    for (src, cls), g in anom.groupby(["src", "ml_class"]):
        if cls not in attack_label:  # classifier still thinks benign -> don't alert
            suppressed += len(g)
            continue
        if len(g) < ANOMALY_MIN_FLOWS:
            continue
        dst = g["dst"].mode().iat[0]
        mean_sc = float(g["anomaly_score"].mean())
        conf = float(g["ml_confidence"].mean())
        sev = "high" if mean_sc > 0.3 else "medium"
        events.append({
            "type": f"ML Anomaly - {attack_label[cls]}", "src": src, "dst": dst,
            "start": float(g["start_rel"].min()), "end": float(g["end_rel"].max()),
            "severity": sev, "confidence": round(min(0.95, 0.4 + conf / 2), 2),
            "reason": (f"{len(g)} flows from {src} were flagged as statistical outliers "
                       f"by the Isolation Forest (mean anomaly score {mean_sc:.2f}) and the "
                       f"classifier labels them '{cls}'. Behaviour deviates from the benign "
                       f"baseline - caught by the ML layer even where no fixed rule matched."),
            "evidence": {"anomalous_flows": int(len(g)),
                         "mean_anomaly_score": round(mean_sc, 3),
                         "ml_class": cls, "mean_class_prob": round(conf, 3)},
            "rule": "ISOLATION_FOREST+RF", "layer": "ml",
        })
    meta["suppressed_benign_anomalies"] = int(suppressed)
    return events


def _fuse(rule_events, ml_events):
    """Merge rule and ML alerts.

    * Same src+dst: keep the rule alert, boost its confidence (corroboration).
    * ML alert whose destination is already covered by a rule alert of the same
      family (e.g. per-source flood alerts behind one DoS rule alert): drop it as
      redundant, but note the corroboration on the rule alert.
    * Otherwise: keep the ML alert (it found something the rules did not).
    """
    fused = [dict(e) for e in rule_events]
    fam_of = {"ML Anomaly - DoS-like": "Denial-of-Service (SYN flood)",
              "ML Anomaly - Scan-like": "Port Scan (reconnaissance)",
              "ML Anomaly - Brute-force-like": "SSH Brute-force"}
    for me in ml_events:
        rule_type = fam_of.get(me["type"])
        me_dst = str(me["dst"]).split(":")[0]
        covered = None
        for re in fused:
            if re["layer"] != "rule":
                continue
            re_dst = str(re.get("dst", "")).split(":")[0]
            same_src = re.get("src") == me["src"]
            same_target_family = (re["type"] == rule_type and re_dst == me_dst)
            if same_src or same_target_family:
                covered = re
                break
        if covered:
            covered["confidence"] = round(min(0.99, covered["confidence"] + 0.1), 2)
            covered["corroborated_by_ml"] = True
        else:
            fused.append(me)
    return fused


def analyze(pcap_path, model=None, model_path="models/hybrid.joblib"):
    """Run the full hybrid pipeline on one pcap and return (alerts, frame, meta)."""
    df, arp_df, meta = build_feature_frame(pcap_path)
    rule_events = run_rules(df, arp_df, meta)

    ml_events = []
    if model is None and Path(model_path).exists():
        model = HybridModel.load(model_path)
    if model is not None and not df.empty:
        df = model.predict_frame(df)
        ml_events = _ml_group_alerts(df, meta)

    alerts = _fuse(rule_events, ml_events)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda e: (severity_rank.get(e["severity"], 9), -e["confidence"]))
    meta["n_flows"] = int(len(df))
    meta["pcap"] = Path(pcap_path).name
    if not df.empty:
        meta["duration"] = round(float(df["end_rel"].max() - df["start_rel"].min()), 1)
    return alerts, df, meta
