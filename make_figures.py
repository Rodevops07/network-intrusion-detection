"""Render figures for the report and video from results/metrics.json."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

M = json.loads(Path("results/metrics.json").read_text())
Path("results").mkdir(exist_ok=True)
plt.rcParams.update({"font.size": 11, "figure.dpi": 130})


def confusion():
    cm = np.array(M["flow_metrics"]["confusion_matrix"]["matrix"])
    labels = M["flow_metrics"]["confusion_matrix"]["labels"]
    fig, ax = plt.subplots(figsize=(5.5, 4.6))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels)), labels, rotation=30, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    ax.set_title("Flow-level confusion matrix")
    thresh = cm.max() / 2
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{cm[i][j]:,}", ha="center", va="center",
                    color="white" if cm[i][j] > thresh else "black", fontsize=9)
    fig.colorbar(im, fraction=0.046, pad=0.04)
    fig.tight_layout(); fig.savefig("results/confusion_matrix.png"); plt.close(fig)


def per_class():
    pc = M["flow_metrics"]["per_class"]
    classes = list(pc.keys())
    metrics = ["precision", "recall", "f1"]
    x = np.arange(len(classes)); w = 0.25
    fig, ax = plt.subplots(figsize=(6.2, 4))
    for k, m in enumerate(metrics):
        ax.bar(x + (k - 1) * w, [pc[c][m] for c in classes], w, label=m)
    ax.set_xticks(x, classes, rotation=20); ax.set_ylim(0, 1.08)
    ax.set_title("Per-class detection performance (flow-level)")
    ax.legend(ncol=3, loc="lower center"); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig("results/per_class.png"); plt.close(fig)


def scenarios():
    sc = M["scenarios"]
    names = list(sc.keys())
    alerts = [sc[n]["alerts"] for n in names]
    fig, ax = plt.subplots(figsize=(6.6, 3.8))
    colors = ["#16a34a" if sc[n]["alerts"] == 0 else "#b91c1c" for n in names]
    ax.bar(names, alerts, color=colors)
    for i, v in enumerate(alerts):
        ax.text(i, v + 0.03, str(v), ha="center", fontsize=10)
    ax.set_title("Alerts raised per scenario (S1 benign = 0 is correct)")
    ax.set_ylabel("alerts"); plt.xticks(rotation=20, ha="right")
    fig.tight_layout(); fig.savefig("results/scenarios.png"); plt.close(fig)


confusion(); per_class(); scenarios()
print("Figures written to results/*.png")
