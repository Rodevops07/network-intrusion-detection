"""Streamlit dashboard for the AI-NIDS.

Run:  streamlit run dashboard.py
Lets an analyst pick a capture, run the hybrid detector, and inspect flagged
events with their full explanation, plus the traffic overview and flow table.
"""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from nids.detect import analyze
from nids.features import ML_FEATURES

st.set_page_config(page_title="AI-NIDS", page_icon="shield", layout="wide")

SEV_BADGE = {"critical": ("#7f1d1d", "CRITICAL"), "high": ("#b91c1c", "HIGH"),
             "medium": ("#b45309", "MEDIUM"), "low": ("#0e7490", "LOW")}
DATA = Path("data")
MODEL = "models/hybrid.joblib"


@st.cache_data(show_spinner=True)
def run_detection(pcap_str):
    alerts, df, meta = analyze(pcap_str, model_path=MODEL)
    return alerts, df, meta


def sev_chip(sev):
    color, label = SEV_BADGE.get(sev, ("#374151", sev.upper()))
    return f"<span style='background:{color};color:white;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600'>{label}</span>"


st.title("AI-Driven Network Intrusion Detection System")
st.caption("Hybrid signature + machine-learning detection with per-alert explainability")

with st.sidebar:
    st.header("Capture")
    caps = sorted(DATA.glob("*.pcap")) if DATA.exists() else []
    if not caps:
        st.error("No pcaps in data/. Run: python -m nids.traffic_gen data")
        st.stop()
    labels = {
        "s1_normal.pcap": "Scenario 1 - Normal baseline",
        "s2_portscan.pcap": "Scenario 2 - Port scan",
        "s3_dos.pcap": "Scenario 3 - DoS (SYN flood)",
        "s4_bruteforce.pcap": "Scenario 4 - SSH brute-force",
        "s5_ambiguous.pcap": "Scenario 5 - Evasive (slow scan + ARP)",
        "mixed_train.pcap": "Mixed (training capture)",
    }
    choice = st.selectbox("Select traffic capture", caps,
                          format_func=lambda p: labels.get(p.name, p.name))
    go = st.button("Run detection", type="primary", use_container_width=True)
    if Path(MODEL).exists():
        st.success("ML model loaded")
    else:
        st.warning("No ML model - rule layer only. Run: python train.py")

if go or "last" not in st.session_state:
    alerts, df, meta = run_detection(str(choice))
    st.session_state["last"] = (str(choice), alerts, df.to_json(), meta)

pcap_str, alerts, df_json, meta = st.session_state["last"]
df = pd.read_json(df_json) if df_json else pd.DataFrame()

# ---- summary tiles
c1, c2, c3, c4 = st.columns(4)
c1.metric("Flows analysed", f"{meta.get('n_flows', 0):,}")
c2.metric("Capture duration", f"{meta.get('duration', '?')} s")
c3.metric("Alerts raised", len(alerts))
crit = sum(1 for a in alerts if a["severity"] in ("critical", "high"))
c4.metric("High / critical", crit)

if meta.get("suppressed_benign_anomalies"):
    st.info(f"ML flagged {meta['suppressed_benign_anomalies']} benign flows as statistical "
            f"outliers (big downloads / monitoring host). These are gated behind the classifier "
            f"and NOT raised as alerts - this is our false-positive control.")

tab_alerts, tab_traffic, tab_flows = st.tabs(["Flagged events", "Traffic overview", "Flow table"])

with tab_alerts:
    if not alerts:
        st.success("No intrusions detected - traffic is consistent with the benign baseline.")
    for i, a in enumerate(alerts, 1):
        with st.container(border=True):
            top = st.columns([6, 1])
            top[0].markdown(f"### #{i} {a['type']}")
            top[1].markdown(sev_chip(a["severity"]), unsafe_allow_html=True)
            m = st.columns(4)
            m[0].markdown(f"**Source**\n\n{a['src']}")
            m[1].markdown(f"**Target**\n\n{a['dst']}")
            m[2].markdown(f"**Window**\n\n{a['start']:.1f}s - {a['end']:.1f}s")
            layer = "Signature (rule)" if a["layer"] == "rule" else "ML (anomaly)"
            extra = " + ML" if a.get("corroborated_by_ml") else ""
            m[3].markdown(f"**Detected by**\n\n{layer}{extra}")
            st.progress(min(a["confidence"], 1.0),
                        text=f"Confidence: {a['confidence']*100:.0f}%")
            st.markdown(f"**Why flagged:** {a['reason']}")
            with st.expander("Evidence & rule"):
                st.json(a["evidence"])
                st.caption(f"Rule / model: {a.get('rule', '-')}")

with tab_traffic:
    if df.empty:
        st.info("No flows.")
    else:
        left, right = st.columns(2)
        with left:
            st.subheader("Protocol distribution")
            st.bar_chart(df["proto"].value_counts())
        with right:
            st.subheader("Top talkers (by flows)")
            st.bar_chart(df["src"].value_counts().head(8))
        st.subheader("Flows over time (10s bins)")
        tl = df.copy()
        tl["bin"] = (tl["start_rel"] // 10 * 10).astype(int)
        st.line_chart(tl.groupby("bin").size().rename("flows"))

with tab_flows:
    if df.empty:
        st.info("No flows.")
    else:
        cols = ["src", "dst", "dport", "proto", "tot_pkts", "tot_bytes",
                "pkts_per_s", "win_dst_ports", "syn_no_reply"]
        if "anomaly_score" in df:
            cols += ["anomaly_score", "ml_class", "ml_confidence"]
        show = df[cols].copy()
        only_anom = st.checkbox("Show only ML-flagged anomalies")
        if only_anom and "is_anomaly" in df:
            show = show[df["is_anomaly"] == 1]
        st.dataframe(show.sort_values("win_dst_ports", ascending=False),
                     use_container_width=True, height=400)
