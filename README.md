# AI-Driven Network Traffic Analysis and Intrusion Detection System

A hybrid **signature + machine-learning** intrusion detection system (IDS) that
ingests network traffic (`.pcap`), extracts per-flow behavioural features, and
flags intrusions with a **human-readable explanation, evidence, and a
confidence/severity** for every alert — so a security analyst can act on *why*,
not just *what*.

> Built for the MegaMinds IT Services — Cybersecurity & Network Security Research
> Intern practical assessment (Round 1).

---

## 1. What it does

| Stage | Module | Summary |
|-------|--------|---------|
| Traffic data | `nids/traffic_gen.py` | Builds a simulated LAN and writes benign + attack pcaps (offline synthesis; nothing is sent on a real network). |
| Feature extraction | `nids/features.py` | Groups packets into bidirectional **flows** and computes ~31 numeric features (rates, durations, TCP-flag mix, per-source window behaviour). |
| Detection — signature | `nids/rules.py` | Transparent threshold rules for port scan, SYN-flood DoS, SSH brute-force, ARP spoofing. |
| Detection — ML | `nids/models.py` | **Isolation Forest** (unsupervised anomaly) + **Random Forest** (supervised attack-family classifier). |
| Fusion + output | `nids/detect.py` | Combines both layers, de-duplicates, ranks by severity, attaches explanations. |
| Interfaces | `cli.py`, `dashboard.py` | Command-line report and a Streamlit analyst dashboard. |
| Evaluation | `evaluate.py`, `make_figures.py` | Precision/recall/F1, confusion matrix, per-scenario outcomes. |

### Attacks covered
Port scanning (reconnaissance), SYN-flood denial-of-service, SSH brute-force,
and ARP spoofing / MITM — plus a deliberately **evasive slow scan** used to
demonstrate a real detection limitation (Scenario 5).

---

## 2. Why hybrid?

- **Signature/rule layer** is fast and perfectly explainable, and nails the
  textbook shape of known attacks — but fixed thresholds miss anything tuned to
  evade them.
- **ML layer** learns what *normal* looks like and flags deviations, so it can
  catch behaviour no rule was written for. In **Scenario 5** the slow scan slips
  under the rate-based rule, and the **ML layer catches it** — exactly the gap a
  hybrid is meant to close.

The two layers also **corroborate** each other: when both fire on the same
event, confidence is raised and the alert is marked `rule + ML`.

---

## 3. Results (summary)

Evaluated on five held-out scenario captures (49,392 flows total):

| Metric (attack vs. benign) | Value |
|---|---|
| Precision | **0.998** |
| Recall | **1.000** |
| F1 | **0.999** |
| Overall accuracy | **0.999** |

| Scenario | Flows | Alerts | Outcome |
|---|---|---|---|
| 1 — Normal baseline | 3,223 | **0** | Clean (no false alarms) ✅ |
| 2 — Port scan | 3,022 | 1 | Port Scan detected (99% conf.) ✅ |
| 3 — SYN-flood DoS | 26,727 | 1 | DoS detected, impact measured ✅ |
| 4 — SSH brute-force | 2,405 | 1 | Brute-force detected ✅ |
| 5 — Evasive (slow scan + ARP) | 3,380 | 2 | Rule **misses** slow scan; **ML catches** it; ARP spoof caught ⚠️ |

The only residual error is **55 benign flows during the DoS window** counted as
`dos` (collateral traffic to the flooded server). See the technical report for
the full discussion. Figures: `results/confusion_matrix.png`,
`results/per_class.png`, `results/scenarios.png`.

---

## 4. Setup

Requires **Python 3.9+**. (Scapy only *reads/writes* pcap files here, so no root
privileges or live capture are needed.)

```bash
cd ai-nids
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 5. Reproduce everything (4 commands)

```bash
# 1. Generate the traffic captures (benign + attacks) into data/
python -m nids.traffic_gen data

# 2. Train the hybrid ML models -> models/hybrid.joblib
python train.py

# 3. Evaluate across all scenarios -> results/metrics.json + console report
python evaluate.py

# 4. (optional) render the result figures -> results/*.png
python make_figures.py
```

## 6. Run detection

**Command line:**
```bash
python cli.py data/s2_portscan.pcap        # formatted analyst report
python cli.py data/s3_dos.pcap --json      # machine-readable
python cli.py --list                       # list captures
```

**Dashboard:**
```bash
streamlit run dashboard.py                 # opens http://localhost:8501
```
Pick a capture in the sidebar, click **Run detection**, and inspect flagged
events, the traffic overview, and the flow table.

You can also point the tools at **your own capture**:
`python cli.py /path/to/your.pcap` (no labels file needed for detection).

---

## 7. Repository layout

```
ai-nids/
├── nids/
│   ├── traffic_gen.py   # simulated LAN + attack pcap synthesis
│   ├── features.py      # packet -> per-flow feature extraction
│   ├── rules.py         # signature / threshold detection layer
│   ├── models.py        # Isolation Forest + Random Forest
│   ├── labeling.py      # ground-truth mapping (training/eval only)
│   └── detect.py        # hybrid fusion + explainable alerts
├── cli.py               # command-line interface
├── dashboard.py         # Streamlit analyst dashboard
├── train.py             # train + persist the ML models
├── evaluate.py          # performance evaluation across scenarios
├── make_figures.py      # result figures for the report/video
├── requirements.txt
├── data/                # pcaps (git-ignored; regenerate) + *.labels.json
├── models/              # trained model (git-ignored; retrain)
└── results/             # metrics.json + figures
```

> **Note on data:** pcaps are large and git-ignored; regenerate them with the
> command above. The small `*.labels.json` ground-truth files are kept so the
> dataset's contents are documented in-repo.

---

## 8. Technology & justification (short)

- **Python** — the de-facto language for both networking (Scapy) and ML (scikit-learn).
- **Scapy** — read/write pcaps and model packets precisely, with no root needed.
- **scikit-learn** — Isolation Forest (anomaly) + Random Forest (classifier):
  robust, fast, and the Random Forest exposes **feature importances**, which
  feeds the explainability requirement.
- **Streamlit** — a dashboard in pure Python, ideal for an analyst view.

Full justification, methodology, and limitations are in
[`TECHNICAL_REPORT.md`](TECHNICAL_REPORT.md).

---

## 9. Limitations (headline)

Synthetic traffic is cleaner and more separable than production traffic, so the
reported scores are an **upper bound**. Rate-based rules are evadable by
low-and-slow attacks (shown in Scenario 5). Encrypted payloads, NAT, and
higher-throughput links would each need more work. See the report for the
complete list and proposed improvements.
