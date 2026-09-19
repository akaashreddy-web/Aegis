import os, re
from datetime import datetime, timezone
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from streamlit_autorefresh import st_autorefresh
from triage.log_parser import parse_logs
from triage.mitre_mapper import map_to_mitre
from aegis.triage.report_generator import generate_report

st.set_page_config(page_title="AEGIS // SOC Defense", page_icon="🛡️", layout="wide")
st_autorefresh(interval=5000, key="auto_refresh")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE, "data", "logs.txt")

for k, v in [("report", None), ("mitre", []), ("lvl", "LOW"), ("prof", "UNKNOWN"), ("score", 1)]:
    if k not in st.session_state: st.session_state[k] = v

st.markdown("""<style>
html, body, [class*="css"] { background: #0a0e1a !important; color: #e5e7eb !important; font-family: monospace; }
#MainMenu, header, footer { visibility: hidden; }
.card { background: #111827; border: 1px solid #00f0ff44; padding: 14px; border-radius: 8px; text-align: center; }
.term { background: #05070d; border: 1px solid #1f293d; padding: 12px; height: 320px; overflow-y: auto; color: #39ff14; font-size: 0.8rem; }
.pill { background: #00f0ff22; border: 1px solid #00f0ff; color: #00f0ff; padding: 2px 8px; border-radius: 10px; font-weight: bold; }
</style>""", unsafe_allow_html=True)

logs = parse_logs(LOG_FILE)
st.markdown(f"""<div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #00f0ff44; padding-bottom:10px; margin-bottom:15px;">
<div><span style="font-size:2rem; font-weight:900; color:#00f0ff;">🛡️ AEGIS</span><br><small style="color:#6b7280;">ACTIVE DEFENSE & THREAT TRIAGE</small></div>
<div style="text-align:right;"><span style="color:#ff073a;">● LIVE</span> PORT 2222<br><small style="color:#00f0ff;">{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}</small></div>
</div>""", unsafe_allow_html=True)

b1, b2, b3 = st.columns([2, 1, 1])
with b1:
    if st.button("🚀 RUN TRIAGE", use_container_width=True):
        cmds = [x["cmd"] for x in logs if x.get("cmd")]
        if cmds:
            mit = map_to_mitre(cmds)
            rep = generate_report(cmds, mit)
            st.session_state.report, st.session_state.mitre = rep, mit
            lm = re.search(r"THREAT LEVEL:\s*(\w+)", rep, re.I)
            if lm: st.session_state.lvl = lm.group(1).upper()
            pm = re.search(r"ATTACKER PROFILE:\s*([^\n]+)", rep, re.I)
            if pm: st.session_state.prof = pm.group(1).strip()
            st.session_state.score = {"LOW":2, "MEDIUM":5, "HIGH":8, "CRITICAL":10}.get(st.session_state.lvl, 4)
            st.rerun()
with b2:
    if st.button("🔄 RESET", use_container_width=True):
        with open(LOG_FILE, "w", encoding="utf-8") as f: f.write("")
        st.session_state.report, st.session_state.mitre, st.session_state.lvl = None, [], "LOW"
        st.rerun()
with b3:
    st.download_button("💾 EXPORT", st.session_state.report or "No report", "aegis_report.txt", use_container_width=True)

c1, c2 = st.columns([6, 4])
with c1:
    st.markdown("<b style='color:#00f0ff;'>📡 LIVE ATTACK STREAM</b>", unsafe_allow_html=True)
    m1, m2, m3 = st.columns(3)
    m1.markdown(f'<div class="card"><small>Attacks</small><h3 style="color:#00f0ff; margin:0;">{len(logs)}</h3></div>', unsafe_allow_html=True)
    m2.markdown(f'<div class="card"><small>Unique IPs</small><h3 style="color:#00f0ff; margin:0;">{len(set(x["ip"] for x in logs))}</h3></div>', unsafe_allow_html=True)
    m3.markdown(f'<div class="card"><small>Status</small><h3 style="color:#39ff14; margin:0;">ONLINE</h3></div>', unsafe_allow_html=True)
    t_lines = "".join(f"<div><span style='color:#6b7280;'>[{l['timestamp']}]</span> <span style='color:#00f0ff;'>{l['ip']}</span>: <b>$ {l['cmd']}</b></div>" for l in logs[-20:])
    st.markdown(f'<div class="term" style="margin-top:10px;">{t_lines or "// AWAITING TRAFFIC ON PORT 2222..."}</div>', unsafe_allow_html=True)

with c2:
    st.markdown("<b style='color:#00f0ff;'>⚠️ THREAT LEVEL</b>", unsafe_allow_html=True)
    colors = {"LOW":"#39ff14", "MEDIUM":"#ffd700", "HIGH":"#ff6b1a", "CRITICAL":"#ff073a"}
    clr = colors.get(st.session_state.lvl, "#39ff14")
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value={"LOW":25,"MEDIUM":50,"HIGH":75,"CRITICAL":100}.get(st.session_state.lvl, 25),
        number={'font':{'color':'rgba(0,0,0,0)'}},
        gauge={'bar':{'color':clr}, 'steps':[{'range':[0,100],'color':'#111827'}]}
    ))
    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', height=170, margin=dict(l=10,r=10,t=10,b=10),
                      annotations=[dict(text=f"<b style='color:{clr}; font-size:22px;'>{st.session_state.lvl}</b>", x=0.5, y=0.2, showarrow=False)])
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar':False})
    st.markdown(f'<div class="card" style="text-align:left;"><b>PROFILE:</b> {st.session_state.prof}<br><small>Score: {st.session_state.score}/10</small></div>', unsafe_allow_html=True)

s1, s2 = st.columns(2)
with s1:
    st.markdown("<b style='color:#00f0ff;'>🎯 MITRE ATT&CK</b>", unsafe_allow_html=True)
    if st.session_state.mitre:
        tbl = "".join(f"<tr><td><span class='pill'>{x.get('technique_id')}</span></td><td>{x.get('technique_name')}</td><td><code>{x.get('evidence')}</code></td></tr>" for x in st.session_state.mitre)
        st.markdown(f"<table style='width:100%; font-size:0.8rem;'><tr><th>ID</th><th>Name</th><th>Cmd</th></tr>{tbl}</table>", unsafe_allow_html=True)
    else: st.info("Run Triage to extract MITRE techniques.")

with s2:
    st.markdown("<b style='color:#00f0ff;'>🧠 AI REPORT</b>", unsafe_allow_html=True)
    if st.session_state.report:
        st.markdown(f"<div style='background:#111827; border:1px solid #00f0ff44; padding:12px; border-radius:6px; font-size:0.85rem;'>{st.session_state.report.replace(chr(10), '<br>')}</div>", unsafe_allow_html=True)
    else: st.info("Awaiting triage execution.")
