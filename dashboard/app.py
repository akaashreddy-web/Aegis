import os
import re
import html
from collections import Counter
from datetime import datetime, timezone

import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from dotenv import load_dotenv

from aegis.triage.log_parser import parse_logs
from aegis.triage.mitre_mapper import map_to_mitre
from aegis.triage.report_generator import generate_report
from aegis.storage import clear_events, fetch_events

COLOR_BG = "#040711"
PANEL_BG = "rgba(10, 16, 30, 0.86)"
CYAN_NEON = "#00f0ff"
ORANGE_WARN = "#ff7700"
RED_ALERT = "#ff003c"
GREEN_NEON = "#00ff66"
YELLOW_GLOW = "#ffd000"
TEXT_WHITE = "#e6edf3"
TEXT_DIM = "#707e94"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(ROOT, "aegis", "data", "logs.txt")
load_dotenv(os.path.join(ROOT, ".env"))

st.set_page_config(page_title="AEGIS // TACTICAL SOC HUD", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
st_autorefresh(interval=5000, key="aegis-hud-refresh")

dashboard_password = os.getenv("AEGIS_DASHBOARD_PASSWORD", "").strip()
if dashboard_password and not st.session_state.get("dashboard_authenticated", False):
    st.markdown("<div style='max-width:420px;margin:12vh auto;padding:2rem;background:#0a101e;border:1px solid #00f0ff55;border-radius:8px;text-align:center'><h2 style='color:#00f0ff;font-family:Orbitron'>AEGIS ACCESS</h2><p style='color:#707e94'>Authorized operators only.</p></div>", unsafe_allow_html=True)
    entered_password = st.text_input("Dashboard password", type="password")
    if st.button("AUTHENTICATE", use_container_width=True):
        if entered_password == dashboard_password:
            st.session_state.dashboard_authenticated = True
            st.rerun()
        st.error("Authentication failed.")
    st.stop()

for key, value in (("report", ""), ("mitre", []), ("level", "LOW"), ("profile", "unknown"), ("score", 1)):
    st.session_state.setdefault(key, value)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;700;900&family=JetBrains+Mono:wght@400;600;800&family=Orbitron:wght@700;900&display=swap');
html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stAppViewContainer"] > section, [class*="css"] {
    background: #040711 !important;
    color: #e6edf3 !important;
    font-family: 'Chakra Petch', sans-serif !important;
}
[data-testid="stAppViewContainer"] {
    background-image: radial-gradient(circle at top, rgba(0,240,255,.09), transparent 38%),
        linear-gradient(rgba(0,240,255,.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,240,255,.02) 1px, transparent 1px) !important;
    background-size: 100% 100%, 24px 24px, 24px 24px !important;
}
[data-testid="stHeader"] { background: transparent; }
#MainMenu, header, footer { visibility: hidden !important; }
.block-container {
    max-width: 1480px;
    padding-top: 1rem;
    padding-bottom: 2rem;
}
.aegis-header {
    background: linear-gradient(180deg, rgba(9,15,27,.96), rgba(8,12,22,.88));
    border: 1px solid rgba(0,240,255,.28);
    border-radius: 14px;
    padding: 16px 22px;
    margin-bottom: 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 0 0 1px rgba(0,240,255,.06), 0 18px 40px rgba(0,0,0,.35);
}
.brand-shield {
    font: 900 2.2rem Orbitron, sans-serif;
    color: #00f0ff;
    letter-spacing: 4px;
    text-shadow: 0 0 18px rgba(0,240,255,.4), 0 0 36px rgba(0,240,255,.2);
}
.tactical-panel {
    background: rgba(9,15,27,.82);
    border: 1px solid rgba(0,240,255,.18);
    border-radius: 12px;
    padding: 18px 18px 12px;
    margin-bottom: 16px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.03), 0 10px 28px rgba(1,4,12,.48);
}
.panel-label {
    font: 700 .82rem Orbitron, sans-serif;
    color: #00f0ff;
    letter-spacing: 2px;
    margin-bottom: 12px;
    display: flex;
    gap: 8px;
    align-items: center;
    text-transform: uppercase;
}
.term-chrome {
    background: #02060d;
    border: 1px solid rgba(0,240,255,.18);
    border-radius: 10px;
    overflow: hidden;
}
.term-bar {
    background: rgba(11,18,32,.9);
    padding: 8px 12px;
    display: flex;
    align-items: center;
    gap: 6px;
    border-bottom: 1px solid rgba(0,240,255,.12);
}
.term-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    display: inline-block;
}
.term-screen {
    height: 300px;
    overflow-y: auto;
    padding: 14px 14px 10px;
    font: 500 .76rem/1.6 'JetBrains Mono', monospace;
    color: #dfeaf5;
}
.metric-box {
    background: rgba(8,13,24,.84);
    border: 1px solid rgba(0,240,255,.16);
    border-radius: 10px;
    padding: 12px 10px;
    text-align: center;
    min-height: 92px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.02);
}
.metric-title {
    color: #7d8899;
    font-size: .68rem;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    margin-bottom: 6px;
}
.metric-val {
    font: 700 1.3rem Orbitron, sans-serif;
    color: #00f0ff;
    white-space: nowrap;
}
.mitre-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0 6px;
    font-size: .78rem;
}
.mitre-table th {
    color: #00f0ff;
    font: 700 .72rem Orbitron, sans-serif;
    letter-spacing: 1.2px;
    text-align: left;
    padding: 8px 12px;
    border-bottom: 1px solid rgba(0,240,255,.16);
}
.mitre-table td {
    background: rgba(7,12,24,.88);
    padding: 10px 12px;
    border-top: 1px solid rgba(0,240,255,.08);
    border-bottom: 1px solid rgba(0,240,255,.08);
}
.mitre-pill {
    background: rgba(0,240,255,.1);
    border: 1px solid #00f0ff;
    color: #00f0ff;
    font: 700 .68rem 'JetBrains Mono', monospace;
    padding: 3px 7px;
    border-radius: 5px;
}
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background: rgba(5,10,20,.75);
    padding: 6px;
    border: 1px solid rgba(0,240,255,.16);
    border-radius: 10px;
}
.stTabs [data-baseweb="tab"] {
    height: 2.7rem;
    padding: 0 1.2rem;
    color: #7d8899;
    font: 700 .75rem Orbitron, sans-serif;
    letter-spacing: 1.2px;
}
.stTabs [aria-selected="true"] {
    color: #00f0ff;
    background: rgba(0,240,255,.08);
    border-radius: 8px;
}
.stTabs [data-baseweb="tab-highlight"] { background: #00f0ff; height: 2px; }
.command-note {
    color: #9aa8bb;
    font-size: .78rem;
    padding: .2rem 0 .75rem;
}
.alert-banner {
    border: 1px solid rgba(255,0,60,.5);
    background: rgba(255,0,60,.12);
    color: #ff9ab0;
    border-radius: 10px;
    padding: .9rem 1rem;
    margin: 0 0 16px;
    font: 700 .78rem 'JetBrains Mono', monospace;
    box-shadow: 0 0 18px rgba(255,0,60,.12);
}
div.stButton > button {
    background: rgba(0,240,255,.08) !important;
    border: 1px solid #00f0ff !important;
    color: #00f0ff !important;
    font: 700 .8rem Orbitron, sans-serif !important;
    letter-spacing: 1.2px !important;
    border-radius: 8px !important;
    min-height: 2.5rem;
    box-shadow: 0 0 0 rgba(0,0,0,0) !important;
}
div.stButton > button:hover {
    background: rgba(0,240,255,.18) !important;
    color: #dffbff !important;
    box-shadow: 0 0 20px rgba(0,240,255,.2) !important;
}
div.stDownloadButton > button {
    background: rgba(0,255,102,.08) !important;
    border: 1px solid #00ff66 !important;
    color: #00ff66 !important;
    font: 700 .8rem Orbitron, sans-serif !important;
    border-radius: 8px !important;
    min-height: 2.5rem;
}
div.stDownloadButton > button:disabled {
    border-color: #334155 !important;
    color: #64748b !important;
    background: rgba(13,20,34,.9) !important;
}
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #040711; }
::-webkit-scrollbar-thumb { background: rgba(0,240,255,.28); border-radius: 3px; }
@media (max-width: 700px) {
    .aegis-header { align-items: flex-start; flex-direction: column; gap: 10px; }
    .aegis-header > div:last-child { text-align: left !important; }
    .brand-shield { font-size: 1.6rem; letter-spacing: 2px; }
}
</style>
""", unsafe_allow_html=True)


def extract_report_value(report: str, label: str, default: str) -> str:
    match = re.search(rf"{label}:\s*([^\n]+)", report, re.IGNORECASE)
    return match.group(1).strip() if match else default


def refresh_analysis(logs: list[dict[str, str]], web_events: list[dict]) -> None:
    commands = [entry["cmd"] for entry in logs if entry.get("cmd")]
    web_signals = [f"WEB {event.get('method', 'GET')} {event.get('path', '/')}" for event in web_events]
    analysis_inputs = commands + web_signals
    if not analysis_inputs:
        st.warning("No commands have been captured yet.")
        return
    with st.spinner("Analyzing attack patterns..."):
        hits = map_to_mitre(analysis_inputs)
        report = generate_report(analysis_inputs, hits)
    level = extract_report_value(report, "THREAT LEVEL", "LOW").upper()
    st.session_state.mitre = hits
    st.session_state.report = report
    st.session_state.level = level if level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "LOW"
    st.session_state.profile = extract_report_value(report, "ATTACKER PROFILE", "unknown")
    st.session_state.score = {"LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}[st.session_state.level]
    st.toast("Analysis complete.")


logs = parse_logs(LOG_FILE)
all_events = fetch_events(500)
web_events = [event for event in all_events if event.get("event_type") == "web_request"]
alert_events = [event for event in all_events if event.get("severity") in {"HIGH", "CRITICAL"}]
if not st.session_state.report and all_events:
    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    observed_level = max((event.get("severity", "LOW") for event in all_events), key=lambda item: severity_order.get(item, 0))
    st.session_state.level = observed_level
    st.session_state.score = {"LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}[observed_level]
total_attacks = len(logs)
unique_ips = len({entry["ip"] for entry in logs}) if logs else 0
last_seen = logs[-1]["timestamp"].split()[-1] if logs else "--:--:--"
active_status = "ACTIVE" if logs else "STANDBY"
status_color = GREEN_NEON if logs else TEXT_DIM
utc_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
st.markdown(f"<div class='aegis-header'><div><div class='brand-shield'>🛡️ AEGIS</div><div style='color:{TEXT_DIM};font-size:.75rem;letter-spacing:1.2px;'>ACTIVE DEFENSE // THREAT TRIAGE PLATFORM</div></div><div style='text-align:right'><span style='color:{RED_ALERT};font-size:.82rem;font-weight:700'>● LIVE</span><span style='color:{TEXT_WHITE};font-size:.82rem;font-weight:700;margin-left:8px'>Monitoring Port 2222</span><div style='color:{CYAN_NEON};font: .78rem JetBrains Mono;margin-top:4px'>{utc_time}</div></div></div>", unsafe_allow_html=True)
if alert_events:
    critical_count = sum(event.get("severity") == "CRITICAL" for event in alert_events)
    st.markdown(f"<div class='alert-banner'>⚠ ACTIVE ALERTS: {len(alert_events)} high-risk event(s) detected • {critical_count} critical • inspect THREAT INTELLIGENCE</div>", unsafe_allow_html=True)

action_1, action_2, action_3 = st.columns(3)
with action_1:
    if st.button("RUN TRIAGE", use_container_width=True):
        refresh_analysis(logs, web_events)
with action_2:
    if st.button("RESET", use_container_width=True):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        open(LOG_FILE, "w", encoding="utf-8").close()
        clear_events()
        for key, value in (("report", ""), ("mitre", []), ("level", "LOW"), ("profile", "unknown"), ("score", 1)):
            st.session_state[key] = value
        st.rerun()
with action_3:
    st.download_button("EXPORT REPORT", st.session_state.report, "aegis_report.txt", use_container_width=True, disabled=not bool(st.session_state.report))

st.write("")
command_tab, live_tab, web_tab, intelligence_tab = st.tabs(["COMMAND CENTER", "LIVE ATTACK STREAM", "WEB ACTIVITY", "THREAT INTELLIGENCE"])

with command_tab:
    st.markdown("<div class='command-note'>Operational overview. Use the other tabs when you need raw telemetry or analyst detail.</div>", unsafe_allow_html=True)
    overview_left, overview_right = st.columns([6, 4])
    with overview_left:
        posture_color = {"LOW": GREEN_NEON, "MEDIUM": YELLOW_GLOW, "HIGH": ORANGE_WARN, "CRITICAL": RED_ALERT}.get(st.session_state.level, CYAN_NEON)
        posture_items = (("THREAT LEVEL", st.session_state.level, posture_color), ("ATTACKS OBSERVED", total_attacks, CYAN_NEON), ("SOURCE IPS", unique_ips, CYAN_NEON))
        posture_html = "".join(f"<div style='display:flex;justify-content:space-between;padding:.7rem 0;border-bottom:1px solid rgba(0,240,255,.1)'><span style='color:{TEXT_DIM}'>{label}</span><b style='color:{item_color}'>{value}</b></div>" for label, value, item_color in posture_items)
        st.markdown(f"<div class='tactical-panel'><div class='panel-label'><span>◈</span> CURRENT POSTURE</div>{posture_html}<div class='panel-label' style='margin-top:1rem'><span>◌</span> NEXT ACTION</div><div style='color:{TEXT_DIM};line-height:1.6'>Review the live stream for command evidence, then open Threat Intelligence to correlate activity and export the report.</div></div>", unsafe_allow_html=True)
        severity_counts = Counter(event.get("severity", "LOW") for event in all_events)
        severity_colors = {"LOW": GREEN_NEON, "MEDIUM": YELLOW_GLOW, "HIGH": ORANGE_WARN, "CRITICAL": RED_ALERT}
        timeline = go.Figure(go.Bar(
            x=list(severity_counts.keys()),
            y=list(severity_counts.values()),
            marker_color=[severity_colors.get(level_name, CYAN_NEON) for level_name in severity_counts],
        ))
        timeline.update_layout(height=180, margin=dict(l=10,r=10,t=20,b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color=TEXT_DIM, title="EVENT SEVERITY", title_font_color=CYAN_NEON, xaxis_title=None, yaxis_title="Events")
        st.plotly_chart(timeline, use_container_width=True, config={"displayModeBar": False})
    with overview_right:
        st.markdown("<div class='panel-label'><span>⚠️</span> THREAT ASSESSMENT</div>", unsafe_allow_html=True)
        level = st.session_state.level
        colors = {"LOW": GREEN_NEON, "MEDIUM": YELLOW_GLOW, "HIGH": ORANGE_WARN, "CRITICAL": RED_ALERT}
        color = colors[level]
        value = {"LOW":25,"MEDIUM":50,"HIGH":78,"CRITICAL":100}[level]
        figure = go.Figure(go.Indicator(mode="gauge", value=value, gauge={"axis":{"range":[0,100],"visible":False},"bar":{"color":color,"thickness":.22},"bgcolor":"rgba(10,18,36,.9)","borderwidth":2,"bordercolor":"rgba(0,240,255,.2)","steps":[{"range":[0,30],"color":"rgba(0,255,102,.06)"},{"range":[30,65],"color":"rgba(255,208,0,.08)"},{"range":[65,85],"color":"rgba(255,119,0,.12)"},{"range":[85,100],"color":"rgba(255,0,60,.18)"}]}))
        figure.update_layout(height=200, margin=dict(l=10,r=10,t=15,b=0), paper_bgcolor="rgba(0,0,0,0)", annotations=[dict(text=f"<b style='color:{color};font-size:24px'>{level}</b><br><span style='color:{TEXT_DIM};font-size:12px'>{value} / 100</span>", x=.5,y=.3,showarrow=False)])
        st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})
        st.markdown(f"<div class='tactical-panel'><div style='font:.8rem Orbitron;color:{TEXT_WHITE};letter-spacing:1px'>ATTACKER PROFILE</div><div style='color:{YELLOW_GLOW};font-size:1.15rem;font-weight:700;text-transform:uppercase;margin:3px 0'>{st.session_state.profile}</div><div style='color:{TEXT_DIM};font-size:.75rem'>Sophistication: {st.session_state.score} / 10</div></div>", unsafe_allow_html=True)

with live_tab:
    st.markdown("<div class='tactical-panel'><div class='panel-label'><span>👤</span> LIVE ATTACK STREAM</div>", unsafe_allow_html=True)
    ssh_query = st.text_input("Filter SSH commands or IP", placeholder="e.g. whoami, 127.0.0.1", key="ssh-filter")
    visible_logs = [entry for entry in logs if not ssh_query or ssh_query.lower() in f"{entry['cmd']} {entry['ip']} {entry['user']}".lower()]
    metric_1, metric_2, metric_3, metric_4 = st.columns(4)
    for column, value, label, style in ((metric_1,total_attacks,"TOTAL ATTACKS",""),(metric_2,unique_ips,"UNIQUE IPs",""),(metric_3,last_seen,"LAST SEEN","font-size:1.05rem;padding-top:4px;"),(metric_4,active_status,"SESSION STATUS",f"color:{status_color};font-size:1.05rem;padding-top:4px;")):
        column.markdown(f"<div class='metric-box'><div class='metric-title'>{label}</div><div class='metric-val' style='{style}'>{value}</div></div>", unsafe_allow_html=True)
    term_html = "<div class='term-chrome'><div class='term-bar'><span class='term-dot' style='background:#ff5f56'></span><span class='term-dot' style='background:#ffbd2e'></span><span class='term-dot' style='background:#27c93f'></span><span style='font:.7rem JetBrains Mono;color:#707e94;margin-left:6px'>honeypot-ssh: /var/log/ingress.log</span></div><div class='term-screen'>"
    if visible_logs:
        for entry in visible_logs[-20:]:
            term_html += f"<div style='margin-bottom:3px'><span style='color:{GREEN_NEON}'>[{entry['timestamp']}]</span> <span style='color:{CYAN_NEON};font-weight:bold'>{entry['ip']}</span> <span style='color:{YELLOW_GLOW}'>{entry['user']}</span>: <span style='color:#fff;font-weight:700'>$ {entry['cmd']}</span></div>"
    else:
        term_html += f"<div style='color:{TEXT_DIM};text-align:center;padding-top:100px'>// LISTENING FOR INGRESS EVENTS ON 0.0.0.0:2222...</div>"
    st.markdown(term_html + "</div></div></div>", unsafe_allow_html=True)

with web_tab:
    st.markdown("<div class='command-note'>Requests received by the decoy web server on port 8080. Submitted fields are stored as telemetry only and never executed.</div>", unsafe_allow_html=True)
    st.markdown("<div class='tactical-panel'><div class='panel-label'><span>◉</span> WEB REQUEST ACTIVITY</div>", unsafe_allow_html=True)
    web_query = st.text_input("Filter web paths or IPs", placeholder="e.g. /login, 127.0.0.1", key="web-filter")
    visible_web_events = [event for event in web_events if not web_query or web_query.lower() in f"{event.get('path', '')} {event.get('source_ip', '')} {event.get('method', '')}".lower()]
    if visible_web_events:
        rows = "".join(
            f"<tr><td>{html.escape(str(event.get('timestamp', '')))}</td><td><span class='mitre-pill'>{html.escape(str(event.get('method', 'GET')))}</span></td><td style='color:{CYAN_NEON}'>{html.escape(str(event.get('source_ip', '')))}</td><td>{html.escape(str(event.get('path', '/')))}</td><td style='color:{TEXT_DIM}'>{html.escape(str(event.get('user_agent', ''))[:48])}</td></tr>"
            for event in reversed(visible_web_events[:50])
        )
        st.markdown(f"<div style='overflow-x:auto'><table class='mitre-table'><thead><tr><th>TIME</th><th>METHOD</th><th>SOURCE IP</th><th>PATH</th><th>USER AGENT</th></tr></thead><tbody>{rows}</tbody></table></div>", unsafe_allow_html=True)
    else:
        st.markdown(f"<div style='text-align:center;padding:70px 0;color:{TEXT_DIM}'>No web requests yet. Open <code>http://localhost:8080</code> to test the decoy site.</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with intelligence_tab:
    st.markdown("<div class='command-note'>Analyst workspace. Run triage from the command bar above to refresh the mapping and report.</div>", unsafe_allow_html=True)
    mapping, report_column = st.columns(2)
    with mapping:
        st.markdown("<div class='tactical-panel'><div class='panel-label'><span>🎯</span> MITRE ATT&CK MAPPING</div>", unsafe_allow_html=True)
        if st.session_state.mitre:
            rows = "".join(f"<tr><td><span class='mitre-pill'>{hit.get('technique_id','T0000')}</span></td><td style='color:{TEXT_WHITE};font-weight:600'>{hit.get('technique_name','Discovery')}</td><td><code style='color:{CYAN_NEON};background:rgba(0,0,0,.5);padding:2px 6px;border-radius:3px'>{hit.get('evidence','')}</code></td></tr>" for hit in st.session_state.mitre)
            st.markdown(f"<table class='mitre-table'><thead><tr><th>ID</th><th>Name</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>", unsafe_allow_html=True)
        else:
            st.markdown(f"<div style='text-align:center;padding:45px 0;color:{TEXT_DIM}'>Awaiting adversary execution to correlate with MITRE framework...</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with report_column:
        st.markdown("<div class='tactical-panel'><div class='panel-label'><span>🧠</span> AI THREAT REPORT</div>", unsafe_allow_html=True)
        report_content = st.session_state.report.replace(chr(10), "<br>") if st.session_state.report else f"<div style='text-align:center;padding:45px 0;color:{TEXT_DIM}'>No active threat report generated. Click [RUN TRIAGE] to analyze.</div>"
        st.markdown(f"<div style='background:rgba(2,6,14,.7);border:1px solid rgba(0,240,255,.15);border-radius:6px;padding:14px;font:.8rem/1.6 JetBrains Mono;color:{TEXT_WHITE}'>{report_content}</div></div>", unsafe_allow_html=True)