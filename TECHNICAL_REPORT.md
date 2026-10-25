# AI-Driven Network Traffic Analysis and Intrusion Detection System
### Technical Report — MegaMinds IT Services, Cybersecurity Research Intern Assessment (Round 1)

---

## 1. Problem overview

Modern networks face a continuously shifting threat landscape: reconnaissance
scans, denial-of-service floods, credential brute-forcing, and man-in-the-middle
interception. Traditional **signature-based** intrusion detection is precise and
explainable for *known* attacks, but it is blind to novel or deliberately
evasive behaviour because it only matches patterns it was explicitly told about.
Purely **anomaly/ML-based** detection generalises better but tends to be noisy
and hard to explain to an analyst. This project builds a **hybrid** system that
keeps the precision and transparency of rules while adding the generalisation of
machine learning, and — crucially — attaches a clear explanation, evidence, and
a confidence/severity to every alert so a human analyst can investigate quickly.

## 2. Objectives

1. Ingest network traffic (`.pcap`) containing both benign and malicious activity.
2. Extract meaningful, behaviour-level features from that traffic.
3. Detect intrusions using a hybrid signature + ML methodology.
4. Produce **explainable** output: what was flagged, why, with what evidence,
   and how confident/severe it is.
5. Provide a runnable prototype (CLI + dashboard) and an honest evaluation,
   including the cases the system gets wrong.

## 3. Traffic data / dataset description

Rather than rely solely on an aged public dataset, the traffic is **generated in
a controlled, reproducible simulation** (`nids/traffic_gen.py`). This is *offline
pcap synthesis*: Scapy constructs packet objects in memory and serialises them to
`.pcap` files — nothing is transmitted on any real network. This mirrors how
public research datasets (CICIDS2017, UNSW-NB15) were produced in isolated labs,
and gives three advantages: (a) perfect ground truth for every flow, (b) full
control over attack intensity and timing, and (c) one-command reproducibility.

**Simulated topology.** A `/24` LAN (`10.0.0.0/24`) with a gateway, DNS server,
a web server (open ports 22/80/443), an SSH server (22), a benign monitoring
host, twenty client workstations (two of which are SSH admins), and an attacker.

**Benign traffic** is Poisson-driven per client: web browsing (DNS lookup +
HTTPS connections to external hosts), internal web-app use, pings, periodic ARP
cache refreshes, and occasional admin SSH sessions. Full TCP semantics are
modelled (three-way handshake, data segments, ACKs, graceful close). A
Nagios-style monitoring host periodically checks service ports — deliberately
included because its behaviour is mildly *scan-like* and is a realistic source
of false positives to test against.

**Attacks** reproduce the packet-level shape of real tools:

| Attack | Modelled on | Signature in the data |
|---|---|---|
| Port scan | `nmap -sS` | One source SYNs hundreds of distinct ports; closed ports reply RST, open ports SYN/ACK. |
| SYN-flood DoS | `hping3 --flood -S` | High SYN rate from ~200 spoofed sources; handshakes never complete; the target is marked degraded so benign connections in the same window show retransmits/failures. |
| SSH brute-force | `hydra` | Many short SSH connections that complete the handshake but abort the login. |
| ARP spoofing / MITM | `arpspoof` / `ettercap` | Forged "gateway is-at *attacker-MAC*" replies — one IP claimed by two MACs. |
| Slow scan (evasive) | `nmap -T0` | ~40 probes spread one every ~12 s, deliberately below rate thresholds. |

Six captures are produced: one per demonstration scenario plus a longer *mixed*
capture used for training. Each pcap has a sidecar `*.labels.json` recording the
ground-truth attacker, target, and time window.

## 4. System architecture

The pipeline is a linear chain with a fusion step at the end:

```
pcap ─▶ feature extraction ─┬─▶ rule layer (signatures) ─┐
                            └─▶ ML layer (IF + RF)       ├─▶ fusion ─▶ ranked, explained alerts
                                                          ┘
```

- **Feature extraction** (`features.py`) streams the pcap, assembles
  bidirectional flows, and computes per-flow and per-source-window features.
- **Rule layer** (`rules.py`) applies transparent thresholds.
- **ML layer** (`models.py`) scores each flow for anomaly and predicts its
  attack family.
- **Fusion** (`detect.py`) merges the two, removes redundancy, corroborates
  overlapping hits, ranks by severity, and emits explainable alerts.

Two interfaces consume the result: a `rich` CLI report and a Streamlit dashboard.

## 5. Feature extraction methodology

A **flow** is one conversation keyed by
`(src_ip, dst_ip, src_port, dst_port, protocol)`, canonicalised so the
"forward" direction is the initiator's, with a 15 s idle timeout. For each flow
we compute ~31 numeric features in four groups:

1. **Volume/size** — total/forward/backward packets and bytes, mean packet size,
   down/up ratio.
2. **Timing** — flow duration, packets-per-second, bytes-per-second, and
   inter-arrival-time statistics (mean/std/min/max).
3. **TCP semantics** — counts of SYN, SYN/ACK, RST, FIN; a `handshake_ok` flag
   (true only when the initiator sends beyond the opening SYN — a spoofed flood
   never does); and `syn_no_reply` (SYN with no response — the scan fingerprint).
4. **Per-source window behaviour** — over a sliding 10 s window per source: the
   number of **distinct destination ports**, distinct destination hosts, flows,
   total SYNs, and unanswered SYNs. Scans and floods are a *source-level*
   phenomenon (one host fanning out), so these window features are what make them
   visible; they turned out to be among the most important features for the model.

Only the numeric behavioural features feed the ML models — **no IP addresses or
ports as identities** — so the models generalise to hosts they never saw rather
than memorising addresses. ARP is handled separately as a layer-2 IP→MAC table.

## 6. Detection methodology

**Signature / rule layer.** Conservative, documented thresholds tuned on the
benign baseline so the noisy monitoring host does not trip them:
- *Port scan*: a source touching ≥ 50 distinct ports within 10 s.
- *SYN flood*: **peak** SYN rate ≥ 150/s toward one `dst:port` (measured over 5 s
  bins, so a short burst inside a long capture is not averaged away) with < 20 %
  of handshakes completing.
- *SSH brute-force*: ≥ 20 SSH connections from one source within 60 s.
- *ARP spoof*: any IP claimed by more than one MAC address.

Each rule emits the triggering numbers as *evidence* and a severity scaled by how
far past the threshold it went.

**ML layer.** Two complementary scikit-learn models, trained on the mixed and
per-scenario captures (54,904 flows):
- **Isolation Forest** (unsupervised, fit on *benign* flows only) learns the
  shape of normal traffic and flags statistical outliers — the mechanism for
  catching behaviour no rule covers.
- **Random Forest** (supervised, class-balanced) names the attack family
  (benign / portscan / dos / bruteforce) and supplies a class probability used as
  confidence. It also exposes feature importances; the top features were
  `max_iat`, `win_dst_ports`, `duration`, `mean_iat`, and `win_syns` — a sensible
  mix of timing and fan-out signals.

**Fusion & explainability.** An ML-only alert is raised only when the Isolation
Forest flags an outlier **and** the Random Forest names an actual attack family;
outliers the classifier still calls benign (large downloads, the monitoring host)
are counted but suppressed, which is the system's primary false-positive control.
When a rule and ML alert cover the same target, the ML alert is folded in and the
rule alert's confidence is boosted and marked *rule + ML*. Every surviving alert
carries: type, source, target, time window, detecting layer, confidence,
severity, a plain-English reason, the numeric evidence, and the rule/model id.

## 7. Testing and evaluation

Scoring is done two ways. **Flow-level**: every flow is given a ground-truth
family from its labels file and a predicted family from the alerts covering it;
we report precision/recall/F1 per class plus a confusion matrix.
**Scenario-level**: did the right alert fire for each scenario, and did the
benign baseline stay clean?

**Results** (49,392 evaluation flows):

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| benign | 1.000 | 0.996 | 0.998 | 13,406 |
| portscan | 1.000 | 1.000 | 1.000 | 1,064 |
| dos | 0.998 | 1.000 | 0.999 | 23,990 |
| bruteforce | 1.000 | 1.000 | 1.000 | 297 |

Attack-vs-benign: **precision 0.998, recall 1.000, F1 0.999, accuracy 0.999.**

Per-scenario: S1 benign → **0 alerts** (no false alarms); S2 port scan, S3 DoS,
S4 brute-force each → exactly **one correct alert**; S5 → ARP spoof caught and the
slow scan caught by the **ML layer** after the rule missed it.

**Mandatory scenarios mapped:**
- *S1 Normal baseline* — clean; the Isolation Forest flagged a handful of benign
  outliers (big downloads) but the classifier gate suppressed them.
- *S2 Reconnaissance* — port scan flagged at 99 % confidence, 339 ports in 10 s.
- *S3 DoS* — SYN flood flagged; the evidence shows the peak rate and the <20 %
  handshake completion, and benign connections in the window show the measurable
  impact (retransmits/failures).
- *S4 Additional attack* — SSH brute-force flagged from the connection burst.
- *S5 Ambiguous/missed* — the low-and-slow scan evades the rate rule (true
  negative at the rule layer), recovered by ML; discussed below.

## 8. Results discussion — what it gets right and wrong

**True positives.** All four primary attacks are detected with high confidence
and specific evidence. The hybrid design visibly pays off in S5.

**False positives.** The only residual error is **55 benign flows during the DoS
window classified as `dos`**. These are legitimate connections to the flooded web
server that fall inside the alert's time window; because the flood degrades those
very connections (they retransmit and stall), they genuinely look abnormal. This
is an honest, bounded 0.2 % cost, not silent over-flagging.

**False / missed negatives.** The slow scan is *missed by the rule layer by
design* — one probe every ~12 s never reaches "50 ports in 10 s". This is the key
limitation the assessment asks to surface: **rate-based signatures are evadable
by patience.** It is recovered here by the anomaly layer, but a determined
attacker could pace below both.

**On the near-perfect scores.** Synthetic traffic is cleaner and more separable
than production traffic, so these numbers are an **upper bound**, not a promise of
real-world accuracy. They validate the *pipeline* (features, rules, models,
fusion, evaluation), not deployment readiness.

## 9. Network & security considerations

- **Inline/real-time cost.** The current system is offline/batch. Inline
  detection adds latency and must keep up with line rate; per-packet flow state
  also consumes memory that an attacker can target.
- **Data completeness.** Detection is only as good as the capture — drops at high
  load, encryption, and asymmetric routing all blind a sensor.
- **Evasion / adversarial traffic.** Low-and-slow scans (shown), fragmentation,
  source spoofing, and traffic shaped to mimic benign flows can defeat fixed
  thresholds and even fool the ML layer.
- **False-positive impact.** In operations, noisy alerts cause fatigue and real
  misses; hence the deliberate classifier gate and severity ranking here.
- **Scalability.** Per-flow, per-source-window state grows with traffic;
  high-throughput networks need sampling, streaming windows, or distributed
  sensors.

## 10. Limitations and future improvements

**Limitations:** synthetic data separability; rate-based rules evadable by slow
attacks; no deep packet inspection or payload/TLS analysis; single-sensor,
offline design; the ML models are trained on this simulation's distribution and
would need retraining on real traffic.

**Future work:** (1) validate on CICIDS2017 / real captures to measure the
synthetic-to-real gap; (2) add streaming, windowed detection for near-real-time
operation; (3) adopt time-window/entropy features that resist slow-scan evasion;
(4) add SHAP-style per-alert feature attribution for even richer explanations;
(5) integrate a signature engine (e.g. Snort/Suricata rules) as a third layer;
(6) add feedback so analyst dispositions retrain the models.

## 11. Conclusion

The system meets the assessment's goal: it ingests traffic, extracts behavioural
features, detects intrusions with a hybrid signature + ML engine, and — most
importantly — **explains every decision** with evidence, confidence, and
severity. It handles the four required attack types, keeps the benign baseline
clean, and is honest about where it fails. The design decisions, the one residual
false-positive class, and the deliberately missed slow scan together show not
just a working prototype but an understanding of *why* detection is hard and
where the trade-offs lie.
