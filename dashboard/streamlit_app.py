"""Enterprise Security Drift Intelligence command center."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.llm_copilot import SecurityCopilot
from backend.pipeline import DriftIntelligencePipeline
from backend.attack_simulation import AttackSimulator


def save_incident_submission(data: dict) -> Path:
    output = ROOT / "reports"
    output.mkdir(parents=True, exist_ok=True)
    path = output / "incident_submissions.csv"
    row = pd.DataFrame([data])
    if path.exists():
        existing = pd.read_csv(path)
        pd.concat([existing, row], ignore_index=True).to_csv(path, index=False)
    else:
        row.to_csv(path, index=False)
    return path

st.set_page_config(
    page_title="SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
}

st.markdown(
    """
    <style>
    .stApp {background: #07111f; color: #e5eefc;}
    [data-testid="stSidebar"] {background: #0b1729;}
    [data-testid="stHeader"] {background: #08131f;}
    [data-testid="stToolbar"] button {background: #0b1729; color: #e5eefc;}
    [data-testid="stMetric"] {
        background: #0d1c31; border: 1px solid #1f3c68; border-radius: 14px; padding: 16px;
    }
    .block-card {
        background: #0d1c31; border: 1px solid #1f3c68;
        border-radius: 16px; padding: 20px; margin-bottom: 20px;
    }
    .block-card h4 {margin: 0 0 10px 0; color: #f8fbff;}
    .section-title {color: #f8fbff; font-size: 1.15rem; margin-bottom: 8px;}
    .soc-note {color: #cbd5e1; font-size: 0.95rem;}
    .stDataFrame div[role="grid"] {background: #0d1c31; color: #e5eefc;}
    .st-bf {background-color: #0d1c31;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner="Running six-layer risk analysis...")
def load_scored_events() -> pd.DataFrame:
    source = pd.read_csv(ROOT / "data" / "config_drift_events.csv")
    pipeline = DriftIntelligencePipeline(ROOT / "models")
    return pipeline.score(source)


events = load_scored_events()

st.sidebar.title("Control Center")
levels = st.sidebar.multiselect(
    "Priority tier",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
)
controls = st.sidebar.multiselect(
    "Control domain",
    sorted(events["control_type"].dropna().unique()),
    default=sorted(events["control_type"].dropna().unique()),
)
compliance = st.sidebar.multiselect(
    "Compliance impact",
    sorted(events["compliance_impact"].fillna("NONE").unique()),
    default=sorted(events["compliance_impact"].fillna("NONE").unique()),
)
anomalies_only = st.sidebar.toggle("Behavioral anomalies only", False)
filtered = events[
    events["priority_level"].isin(levels)
    & events["control_type"].isin(controls)
    & events["compliance_impact"].fillna("NONE").isin(compliance)
]
if anomalies_only:
    filtered = filtered[filtered["anomaly_flag"]]

st.markdown("## SOC Command Center")
st.markdown("#### Enterprise drift detection, analyst triage, and incident submission")

critical = int((filtered["priority_level"] == "CRITICAL").sum())
high = int((filtered["priority_level"] == "HIGH").sum())
anomalies = int(filtered["anomaly_flag"].sum())
compliance_count = int((filtered["compliance_impact"] != "NONE").sum())
open_incidents = len(filtered)

left, middle, right = st.columns([1.5, 1, 1])
with left:
    st.markdown("<div class='block-card'><h4>Current SOC Status</h4><p class='soc-note'>Filtered alerts and investigations are updated in real time from the drift engine.</p></div>", unsafe_allow_html=True)
with middle:
    st.metric("Open Alerts", f"{open_incidents:,}", delta=f"{critical} critical")
with right:
    st.metric("Anomalies", f"{anomalies}", delta=f"{high} high priority")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Events Assessed", f"{len(filtered):,}")
m2.metric("Critical", critical)
m3.metric("High", high)
m4.metric("Compliance Impacts", compliance_count)

tab_exec, tab_drift, tab_compliance, tab_analyst, tab_attack, tab_validation = st.tabs(
    [
        "Executive Summary",
        "Security Drift",
        "Compliance",
        "LLM Analyst",
        "Attack Simulation",
        "Model Assurance",
    ]
)

with tab_exec:
    left, right = st.columns(2)
    distribution = (
        filtered["priority_level"]
        .value_counts()
        .reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"], fill_value=0)
        .reset_index()
    )
    distribution.columns = ["priority_level", "count"]
    left.plotly_chart(
        px.bar(
            distribution,
            x="priority_level",
            y="count",
            color="priority_level",
            color_discrete_map=COLORS,
            title="Enterprise Risk Distribution",
        ).update_layout(showlegend=False, paper_bgcolor="#07111f", plot_bgcolor="#07111f"),
        use_container_width=True,
    )
    control_risk = (
        filtered.groupby("control_type", as_index=False)["priority_score"]
        .mean()
        .sort_values("priority_score", ascending=False)
    )
    right.plotly_chart(
        px.bar(
            control_risk,
            x="priority_score",
            y="control_type",
            orientation="h",
            color="priority_score",
            color_continuous_scale="YlOrRd",
            title="Threat Heatmap by Control Domain",
        ).update_layout(paper_bgcolor="#07111f", plot_bgcolor="#07111f"),
        use_container_width=True,
    )
    st.subheader("Top Priority Alerts")
    top = filtered.nlargest(10, "priority_score")
    st.dataframe(
        top[
            [
                "drift_event_id",
                "control_name",
                "control_type",
                "priority_level",
                "priority_score",
                "matched_rules",
                "status",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

with tab_drift:
    timeline = filtered.copy()
    timeline["change_date"] = pd.to_datetime(timeline["change_date"], errors="coerce")
    st.plotly_chart(
        px.scatter(
            timeline,
            x="change_date",
            y="priority_score",
            color="priority_level",
            size="anomaly_confidence",
            hover_data=["control_type", "change_type", "anomaly_flag"],
            color_discrete_map=COLORS,
            title="Anomaly and Priority Timeline",
        ).update_layout(paper_bgcolor="#07111f", plot_bgcolor="#07111f"),
        use_container_width=True,
    )
    st.subheader("Drift Investigation Queue")
    st.dataframe(
        filtered.sort_values("priority_score", ascending=False),
        column_config={
            "priority_score": st.column_config.ProgressColumn(
                "Priority", min_value=0, max_value=100, format="%.1f"
            ),
            "anomaly_confidence": st.column_config.ProgressColumn(
                "Anomaly Confidence", min_value=0, max_value=100, format="%.1f"
            ),
        },
        use_container_width=True,
        hide_index=True,
    )

with tab_compliance:
    exploded = filtered[["priority_level", "priority_score", "compliance_mappings"]].explode(
        "compliance_mappings"
    )
    exploded = exploded.dropna(subset=["compliance_mappings"])
    if not exploded.empty:
        compliance_summary = (
            exploded.groupby(["compliance_mappings", "priority_level"])
            .size()
            .reset_index(name="alerts")
        )
        st.plotly_chart(
            px.bar(
                compliance_summary,
                x="compliance_mappings",
                y="alerts",
                color="priority_level",
                color_discrete_map=COLORS,
                title="Compliance Control Exposure",
            ).update_layout(paper_bgcolor="#07111f", plot_bgcolor="#07111f"),
            use_container_width=True,
        )
    st.dataframe(
        exploded.sort_values("priority_score", ascending=False),
        use_container_width=True,
        hide_index=True,
    )

with tab_analyst:
    candidate = filtered.sort_values("priority_score", ascending=False)
    if candidate.empty:
        st.info("No alerts match the current filters.")
    else:
        options = candidate.apply(
            lambda row: (
                f"{row.get('drift_event_id', '')} | {row.get('control_name', 'Unknown')} | "
                f"{row['control_type']} | {row['priority_level']} {row['priority_score']:.1f}"
            ),
            axis=1,
        )
        selection = st.selectbox("Select alert", options)
        selected = candidate.loc[options[options == selection].index[0]].to_dict()
        left, right = st.columns([1, 1])
        with left:
            st.subheader("Alert Evidence")
            st.json(
                {
                    key: selected.get(key)
                    for key in [
                        "drift_event_id",
                        "control_name",
                        "control_type",
                        "change_type",
                        "severity",
                        "status",
                        "change_reason",
                        "security_rule_score",
                        "ml_risk_score",
                        "anomaly_confidence",
                        "priority_score",
                        "priority_level",
                        "matched_rules",
                        "compliance_mappings",
                    ]
                }
            )
        with right:
            st.subheader("Security Copilot")
            if st.button("Generate SOC Analysis", type="primary", use_container_width=True):
                with st.spinner("Building evidence-grounded narrative..."):
                    analysis = SecurityCopilot().analyze(selected)
                for key, value in analysis.items():
                    if key != "generation_mode":
                        st.markdown(f"**{key.replace('_', ' ').title()}**")
                        st.write(value)
                st.caption(f"Generation mode: {analysis['generation_mode']}" )

        with st.expander("Submit incident to SOC queue"):
            with st.form("incident_submission_form"):
                incident_title = st.text_input(
                    "Incident title",
                    value=f"SOC Alert: {selected.get('control_name', 'Unknown Control')}"
                )
                incident_priority = st.selectbox(
                    "Incident priority",
                    ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    index=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(
                        selected.get("priority_level", "MEDIUM").upper()
                    ),
                )
                incident_owner = st.text_input("Owner", value="SOC Analyst")
                incident_notes = st.text_area(
                    "Investigation notes",
                    value=(
                        "Review drift evidence, correlate with change approvals, and assign containment actions.\n"
                        f"Matched rules: {selected.get('matched_rules', [])}\n"
                        f"Compliance impacts: {selected.get('compliance_mappings', [])}"
                    ),
                )
                submit_incident = st.form_submit_button("Submit incident")
                if submit_incident:
                    submission = {
                        "incident_title": incident_title,
                        "priority": incident_priority,
                        "owner": incident_owner,
                        "control_name": selected.get("control_name", ""),
                        "control_type": selected.get("control_type", ""),
                        "priority_level": selected.get("priority_level", ""),
                        "priority_score": selected.get("priority_score", ""),
                        "matched_rules": selected.get("matched_rules", []),
                        "compliance_mappings": selected.get("compliance_mappings", []),
                        "incident_notes": incident_notes,
                    }
                    path = save_incident_submission(submission)
                    st.success(f"Incident submitted to {path.name}")
                    st.write(submission)

with tab_attack:
    st.markdown("<div class='block-card'><h4>Attack Simulation</h4><p class='soc-note'>Review simulated adversary behavior and recommended containment actions for prioritized drift events.</p></div>", unsafe_allow_html=True)
    attack_n = st.slider("Number of simulated scenarios", min_value=1, max_value=20, value=5)
    simulator = AttackSimulator()
    attack_scenarios = simulator.generate_scenarios(filtered, top_n=attack_n)
    if attack_scenarios.empty:
        st.info("No attack scenarios could be generated from the current selection.")
    else:
        st.dataframe(
            attack_scenarios[
                [
                    "control_name",
                    "control_type",
                    "priority_level",
                    "priority_score",
                    "attack_pattern",
                    "scenario_description",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )
        with st.expander("Show remediation details"):
            st.dataframe(
                attack_scenarios[
                    [
                        "control_name",
                        "attack_pattern",
                        "recommended_remediation",
                        "recommended_remediation_commands",
                    ]
                ],
                use_container_width=True,
                hide_index=True,
            )

with tab_validation:
    metrics_path = ROOT / "reports" / "model_metrics.json"
    validation_path = ROOT / "reports" / "validation_metrics.json"
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        a, b = st.columns(2)
        a.metric("Cross-Validated Macro F1", f"{metrics['cross_validation_f1_macro_mean']:.3f}")
        b.metric("Training Rows", metrics["training_rows"])
        st.subheader("Explainable AI: Feature Importance")
        st.dataframe(pd.DataFrame(metrics["feature_importance"]), use_container_width=True)
    if validation_path.exists():
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        st.metric(
            "Scenario Validation Accuracy",
            f"{validation['accuracy']:.1%}",
            f"{validation['passed_scenarios']}/{validation['total_scenarios']} passed",
        )
    if not metrics_path.exists() and not validation_path.exists():
        st.info("Run `python scripts/run_pipeline.py` to populate model assurance artifacts.")
