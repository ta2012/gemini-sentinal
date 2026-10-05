import os
import json
import streamlit as st
import pandas as pd

from detect import (
    load_events,
    run_detection_pipeline,
    build_incident_context,
    analyze_with_gemini,
)

st.set_page_config(
    page_title="Gemini Sentinel",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# SESSION STATE
# ============================================================

def init_state():
    defaults = {
        "selected_incident": None,
        "isolated_agents": set(),
        "dismissed_incidents": set(),
        "demo_mode": False,
        "demo_step": 0,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


init_state()

# ============================================================
# STYLE
# ============================================================

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] { font-family: Inter, sans-serif; }
.stApp { background: #070b12; }
.block-container { max-width: 1500px; padding-top: 1.1rem; }

.hero {
    padding: 24px 28px;
    border: 1px solid #263244;
    border-radius: 14px;
    background: linear-gradient(135deg, #0b1220, #0a0f18);
    margin-bottom: 18px;
}
.hero-title { font-size: 2.2rem; font-weight: 800; letter-spacing: -1px; }
.hero-sub { color: #94a3b8; margin-top: 5px; }

.metric-card {
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 15px 17px;
    background: #0c121c;
}

.incident-card {
    border: 1px solid #263244;
    border-radius: 12px;
    padding: 14px;
    background: #0c121c;
    margin-bottom: 8px;
}

.panel {
    border: 1px solid #263244;
    border-radius: 12px;
    padding: 17px;
    background: #0b111b;
}

.chain-step {
    border-left: 3px solid #7c3aed;
    padding: 10px 14px;
    margin: 7px 0;
    background: #101725;
    border-radius: 0 8px 8px 0;
}

.demo-event {
    border: 1px solid #263244;
    border-radius: 10px;
    padding: 12px 14px;
    margin: 7px 0;
    background: #0c121c;
}

.demo-event-active {
    border: 1px solid #dc2626;
    background: #171016;
}

.small-mono {
    font-family: 'JetBrains Mono', monospace;
    font-size: .82rem;
    color: #94a3b8;
}

.status-live { color: #6ee7b7; font-weight: 700; }
.status-fallback { color: #fbbf24; font-weight: 700; }

div[data-testid="stMetric"] {
    background: #0c121c;
    border: 1px solid #1e293b;
    padding: 12px;
    border-radius: 10px;
}
</style>
""",
    unsafe_allow_html=True,
)

# ============================================================
# DATA HELPERS
# ============================================================

def load_incidents(events_file="events.jsonl", force_run=False):
    output = "incidents.json" if events_file == "events.jsonl" else "temp_incidents.json"

    if force_run or not os.path.exists(output):
        with st.spinner("Running Sentinel detection pipeline..."):
            run_detection_pipeline(
                rules_path="rules.yaml",
                events_path=events_file,
                output_path=output,
            )

    with open(output, "r", encoding="utf-8") as f:
        return json.load(f)


def severity_rank(severity):
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }.get(str(severity).lower(), 0)


def summary_for(incident):
    return incident.get("llm_summary") or {}


def risk_for(incident):
    summary = summary_for(incident)
    score = summary.get("risk_score")
    if isinstance(score, (int, float)):
        return int(score)
    return severity_rank(incident.get("severity")) * 25


def build_event_index(incidents):
    event_to_incident = {}
    flagged = set()
    for incident in incidents:
        for finding in incident.get("findings", []):
            for event in finding.get("matched_events", []):
                event_id = event.get("event_id")
                if event_id is not None:
                    flagged.add(event_id)
                    event_to_incident[event_id] = incident
    return flagged, event_to_incident

# ============================================================
# LOAD DATA
# ============================================================

st.sidebar.markdown("## Gemini Sentinel")
st.sidebar.caption("AI-Agent Security Intelligence")
st.sidebar.markdown("---")

uploaded = st.sidebar.file_uploader(
    "Upload agent events",
    type=["jsonl"],
)

events_file = "events.jsonl"

if uploaded is not None:
    events_file = "temp_uploaded_events.jsonl"
    with open(events_file, "wb") as f:
        f.write(uploaded.getbuffer())
    st.sidebar.success("Custom event stream loaded.")

if st.sidebar.button("Re-run Detection", use_container_width=True):
    load_incidents(events_file, force_run=True)
    st.rerun()

incidents = load_incidents(events_file)
raw_events = load_events(events_file)
flagged_event_ids, event_to_incident = build_event_index(incidents)

# ============================================================
# SIDEBAR FILTERS + DEMO CONTROL
# ============================================================

st.sidebar.markdown("---")
st.sidebar.markdown("### Filters")

agents = sorted({e.get("agent_id", "unknown") for e in raw_events})
selected_agents = st.sidebar.multiselect("Agent", agents, default=agents)

severity_filter = st.sidebar.multiselect(
    "Severity",
    ["critical", "high", "medium", "low", "info"],
    default=["critical", "high", "medium", "low", "info"],
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Live Demo")

if st.sidebar.button("Start Attack Simulation", use_container_width=True, type="primary"):
    st.session_state.demo_mode = True
    st.session_state.demo_step = 1
    st.session_state.selected_incident = "INC-004"
    st.rerun()

if st.session_state.demo_mode:
    st.sidebar.caption("Simulation is using the generated attack-chain events.")
    if st.sidebar.button("Reset Simulation", use_container_width=True):
        st.session_state.demo_mode = False
        st.session_state.demo_step = 0
        st.session_state.selected_incident = None
        st.rerun()

# ============================================================
# FILTER INCIDENTS
# ============================================================

filtered_incidents = [
    i for i in incidents
    if i.get("agent_id") in selected_agents
    and str(i.get("severity", "")).lower() in severity_filter
    and i.get("incident_id") not in st.session_state.dismissed_incidents
]

# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
<div class="hero">
    <div class="hero-title">GEMINI SENTINEL</div>
    <div class="hero-sub">AI-Agent Security Intelligence | Detect | Correlate | Reason | Respond</div>
</div>
""",
    unsafe_allow_html=True,
)

# ============================================================
# METRICS
# ============================================================

critical_count = sum(str(i.get("severity", "")).lower() == "critical" for i in filtered_incidents)
high_count = sum(str(i.get("severity", "")).lower() == "high" for i in filtered_incidents)
avg_risk = int(sum(risk_for(i) for i in filtered_incidents) / len(filtered_incidents)) if filtered_incidents else 0

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Events", len(raw_events))
m2.metric("Findings", sum(len(i.get("findings", [])) for i in incidents))
m3.metric("Incidents", len(filtered_incidents))
m4.metric("Critical / High", f"{critical_count} / {high_count}")
m5.metric("Average Risk", f"{avg_risk}/100")

# ============================================================
# ATTACK SIMULATION
# ============================================================

if st.session_state.demo_mode:
    st.markdown("---")
    st.subheader("Live Attack Simulation")
    st.caption("This uses the generated Sentinel attack chain already present in events.jsonl. No real systems or tools are modified.")

    demo_agent = "sentinel-demo-agent-06"
    demo_events = [e for e in raw_events if e.get("agent_id") == demo_agent]

    # Keep chronological order and reveal one event at a time.
    demo_events = sorted(demo_events, key=lambda x: x.get("timestamp", ""))
    visible_count = min(st.session_state.demo_step, len(demo_events))

    for idx, event in enumerate(demo_events[:visible_count], 1):
        action = event.get("action", "")
        tool = event.get("tool_name", "")
        risk_scope = event.get("risk_scope", "")
        source = event.get("memory_source", "")
        label = tool or action

        details = f"{action}"
        if tool:
            details += f" | tool={tool}"
        if risk_scope:
            details += f" | scope={risk_scope}"
        if source:
            details += f" | source={source}"

        finding = None
        incident_for_event = event_to_incident.get(event.get("event_id"))
        if incident_for_event:
            for f in incident_for_event.get("findings", []):
                if any(e.get("event_id") == event.get("event_id") for e in f.get("matched_events", [])):
                    finding = f
                    break

        css = "demo-event demo-event-active" if idx == visible_count else "demo-event"
        finding_text = f" | DETECTED: {finding.get('rule_id')} - {finding.get('name')}" if finding else ""

        st.markdown(
            f"""
            <div class="{css}">
                <b>STEP {idx}</b> &nbsp; {label}<br>
                <span class="small-mono">{event.get('timestamp')} | {details}{finding_text}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    b1, b2, b3 = st.columns([1, 1, 2])
    with b1:
        if visible_count < len(demo_events):
            if st.button("Advance Simulation", use_container_width=True, type="primary"):
                st.session_state.demo_step += 1
                st.rerun()
        else:
            st.success("Attack sequence complete. Sentinel has the full chain available for investigation.")
    with b2:
        if visible_count > 0 and st.button("Show Full Chain", use_container_width=True):
            st.session_state.demo_step = len(demo_events)
            st.rerun()
    with b3:
        st.caption("Demo flow: external input -> memory poisoning -> unauthorized high-risk actions -> attempted evidence removal.")

# ============================================================
# INCIDENT QUEUE + DETAIL
# ============================================================

st.markdown("---")
left, right = st.columns([1.0, 1.8], gap="large")

with left:
    st.subheader("Incident Queue")

    if not filtered_incidents:
        st.info("No incidents match the current filters.")
    else:
        ordered = sorted(
            filtered_incidents,
            key=lambda x: (-severity_rank(x.get("severity")), -risk_for(x)),
        )

        for incident in ordered:
            incident_id = incident["incident_id"]
            severity = str(incident.get("severity", "unknown")).upper()
            risk = risk_for(incident)
            engine = incident.get("analysis_engine", "Rule-Based Fallback")

            st.markdown(
                f"""
                <div class="incident-card">
                    <b>{incident_id}</b> <span style="float:right">{severity}</span><br>
                    <span class="small-mono">Agent: {incident.get('agent_id', 'unknown')} | Risk: {risk}/100</span><br>
                    <span class="small-mono">Engine: {engine}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if st.button("Inspect " + incident_id, key="inspect_" + incident_id, use_container_width=True):
                st.session_state.selected_incident = incident_id
                st.rerun()

with right:
    selected_id = st.session_state.selected_incident

    if selected_id:
        selected_incident = next((i for i in incidents if i.get("incident_id") == selected_id), None)
    else:
        selected_incident = sorted(
            filtered_incidents,
            key=lambda x: (-severity_rank(x.get("severity")), -risk_for(x)),
        )[0] if filtered_incidents else None

    if not selected_incident:
        st.info("Select an incident to inspect.")
    else:
        incident = selected_incident
        summary = summary_for(incident)
        severity = str(incident.get("severity", "unknown")).upper()
        risk = risk_for(incident)
        confidence = summary.get("confidence", 60)
        engine = incident.get("analysis_engine", "Rule-Based Fallback")
        agent_id = incident.get("agent_id", "unknown")

        st.subheader(f"{incident['incident_id']} | {severity}")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk Score", f"{risk}/100")
        c2.metric("Confidence", f"{confidence}%")
        c3.metric("Findings", len(incident.get("findings", [])))
        c4.metric("Agent", agent_id)

        if engine == "Gemini Sentinel":
            st.markdown('<span class="status-live">ANALYZED BY GEMINI SENTINEL</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="status-fallback">RULE-BASED / FALLBACK ANALYSIS</span>', unsafe_allow_html=True)

        st.markdown("---")

        tab1, tab2, tab3, tab4 = st.tabs([
            "Sentinel Analysis",
            "Attack Chain",
            "Evidence",
            "Response",
        ])

        with tab1:
            st.markdown("### Verdict")
            st.info(summary.get("verdict", "No LLM verdict available."))

            st.markdown("### Why is this dangerous?")
            st.write(summary.get("severity_reasoning", "No detailed reasoning is available yet."))

            st.markdown("### Potential Impact")
            st.write(summary.get("potential_impact", "Potential impact requires analyst investigation."))

            st.markdown("### Predicted Next Step")
            st.warning(summary.get("predicted_next_step", "Investigate correlated activity and restrict suspicious agent actions."))

            if st.button("Analyze / Re-analyze with Gemini", key="gemini_" + incident["incident_id"], use_container_width=True):
                with st.spinner("Gemini Sentinel is analyzing the incident..."):
                    try:
                        result = analyze_with_gemini(incident, build_incident_context(incident))
                        incident["llm_summary"] = result
                        incident["analysis_engine"] = "Gemini Sentinel"
                        output = "incidents.json" if events_file == "events.jsonl" else "temp_incidents.json"
                        with open(output, "w", encoding="utf-8") as f:
                            json.dump(incidents, f, indent=2)
                        st.success("Gemini Sentinel analysis completed.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Gemini analysis unavailable: {exc}")

        with tab2:
            st.markdown("### Reconstructed Attack Chain")
            chain = summary.get("attack_chain", [])
            if chain:
                for idx, step in enumerate(chain, 1):
                    st.markdown(
                        f"<div class='chain-step'><b>STEP {idx}</b><br>{step}</div>",
                        unsafe_allow_html=True,
                    )
            else:
                for idx, finding in enumerate(incident.get("findings", []), 1):
                    st.markdown(
                        f"<div class='chain-step'><b>STEP {idx}</b><br>{finding.get('name')} — {finding.get('description', '')}</div>",
                        unsafe_allow_html=True,
                    )

        with tab3:
            st.markdown("### Security Findings")
            for finding in incident.get("findings", []):
                st.markdown(f"**{finding.get('rule_id')} — {finding.get('name')}** | {str(finding.get('severity', '')).upper()}")
                st.caption(finding.get("description", ""))

            st.markdown("### Evidence Highlights")
            evidence = summary.get("evidence", [])
            if evidence:
                for item in evidence:
                    st.markdown(f"- {item}")
            else:
                st.caption("No LLM evidence highlights available.")

        with tab4:
            st.markdown("### Recommended Response")
            st.success(summary.get("suggested_action", "Review permissions and restrict suspicious activity."))

            st.markdown("### Response Priority")
            st.warning(summary.get("response_priority", severity))

            if agent_id in st.session_state.isolated_agents:
                st.success(f"Agent {agent_id} is isolated in demo mode.")
                if st.button("Release Agent", key="release_" + agent_id, use_container_width=True):
                    st.session_state.isolated_agents.remove(agent_id)
                    st.rerun()
            else:
                if st.button("Isolate Agent", key="isolate_" + agent_id, type="primary", use_container_width=True):
                    st.session_state.isolated_agents.add(agent_id)
                    st.rerun()

            if st.button("Resolve Incident", key="resolve_" + incident["incident_id"], use_container_width=True):
                st.session_state.dismissed_incidents.add(incident["incident_id"])
                st.session_state.selected_incident = None
                st.rerun()

# ============================================================
# EVENT STREAM
# ============================================================

st.markdown("---")
st.subheader("Agent Activity Stream")

rows = []
for event in raw_events:
    event_id = event.get("event_id")
    incident = event_to_incident.get(event_id)
    rows.append({
        "Status": "ALERT" if event_id in flagged_event_ids else "OK",
        "Time": event.get("timestamp"),
        "Agent": event.get("agent_id"),
        "Action": event.get("action"),
        "Tool": event.get("tool_name", ""),
        "Risk Scope": event.get("risk_scope", ""),
        "Incident": incident.get("incident_id", "") if incident else "",
    })

df = pd.DataFrame(rows)
if not df.empty:
    st.dataframe(df, use_container_width=True, hide_index=True, height=340)

# ============================================================
# DEMO EXPLANATION
# ============================================================

st.markdown("---")
st.subheader("What the live demo proves")
st.markdown(
    """
<div class="panel">
<b>1. Detect:</b> deterministic rules identify individual security violations.<br><br>
<b>2. Correlate:</b> related findings are grouped into an incident for the same agent.<br><br>
<b>3. Reason:</b> Gemini Sentinel can reconstruct the sequence, assess risk, explain impact, predict the next consequence, and recommend a response.<br><br>
<b>4. Respond:</b> the analyst can isolate or resolve an incident in the demo interface.
</div>
""",
    unsafe_allow_html=True,
)

st.caption("Demo response controls modify only the local Streamlit session. They do not execute real production security actions.")
