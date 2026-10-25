"""Machine-learning detection layer (the behavioural half of the hybrid).

Two complementary models:

  * IsolationForest  - unsupervised anomaly detector. Learns the shape of benign
    flows and flags outliers. Catches novel/unseen behaviour without labels; this
    is what gives the system a chance against attacks no rule was written for.

  * RandomForest     - supervised classifier. Trained on labelled flows to name
    the attack family (portscan / dos / bruteforce) and give a class probability
    used as the confidence. Random Forests are robust, need little tuning, and
    expose feature importances - useful for the explainability requirement.

Both operate on the numeric behavioural features in ML_FEATURES only (no IPs or
ports as identities), so the models generalise to hosts they never saw.
"""
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .features import ML_FEATURES, build_feature_frame
from .labeling import load_truth, label_flows, to_family


class HybridModel:
    def __init__(self):
        self.scaler = None
        self.iforest = None
        self.rf = None
        self.rf_classes = None
        self.importances = None

    # ---- training --------------------------------------------------------
    def fit(self, train_pcaps, contamination=0.03):
        frames = []
        for p in train_pcaps:
            df, arp_df, meta = build_feature_frame(p)
            truth = load_truth(p)
            df = df.copy()
            df["label"] = label_flows(df, truth)
            df["family"] = df["label"].map(to_family)
            frames.append(df)
        data = pd.concat(frames, ignore_index=True)

        X = data[ML_FEATURES].fillna(0).replace([np.inf, -np.inf], 0).values
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X)

        # Anomaly model: fit on benign only, so "normal" is defined by benign.
        benign_mask = (data["family"] == "benign").values
        self.iforest = IsolationForest(
            n_estimators=200, contamination=contamination,
            random_state=42, n_jobs=-1).fit(Xs[benign_mask])

        # Supervised model: all families (benign + attacks).
        y = data["family"].values
        self.rf = RandomForestClassifier(
            n_estimators=300, max_depth=None, class_weight="balanced",
            random_state=42, n_jobs=-1).fit(Xs, y)
        self.rf_classes = list(self.rf.classes_)
        self.importances = dict(sorted(
            zip(ML_FEATURES, self.rf.feature_importances_),
            key=lambda kv: kv[1], reverse=True))
        return self._training_report(data, Xs)

    def _training_report(self, data, Xs):
        from sklearn.metrics import classification_report
        pred = self.rf.predict(Xs)
        rep = classification_report(data["family"].values, pred,
                                    output_dict=True, zero_division=0)
        return {"n_flows": len(data),
                "class_counts": data["family"].value_counts().to_dict(),
                "train_report": rep,
                "top_features": list(self.importances.items())[:10]}

    # ---- inference -------------------------------------------------------
    def predict_frame(self, df):
        """Attach ML predictions to a feature frame: anomaly score + class + prob."""
        if df.empty:
            return df
        X = df[ML_FEATURES].fillna(0).replace([np.inf, -np.inf], 0).values
        Xs = self.scaler.transform(X)
        # IsolationForest: decision_function>0 inlier, <0 outlier. Flip to a 0..1
        # anomaly score where higher = more anomalous.
        raw = self.iforest.decision_function(Xs)
        df = df.copy()
        # higher score = more anomalous; 0 at the inlier/outlier boundary
        df["anomaly_score"] = np.clip(0.5 - raw, 0, None)
        df["is_anomaly"] = (self.iforest.predict(Xs) == -1).astype(int)
        proba = self.rf.predict_proba(Xs)
        df["ml_class"] = self.rf.predict(Xs)
        df["ml_confidence"] = proba.max(axis=1)
        return df

    # ---- persistence -----------------------------------------------------
    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"scaler": self.scaler, "iforest": self.iforest,
                     "rf": self.rf, "rf_classes": self.rf_classes,
                     "importances": self.importances}, path)

    @classmethod
    def load(cls, path):
        d = joblib.load(path)
        m = cls()
        m.scaler, m.iforest, m.rf = d["scaler"], d["iforest"], d["rf"]
        m.rf_classes, m.importances = d["rf_classes"], d["importances"]
        return m
