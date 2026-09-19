import os
from typing import Any
from dotenv import load_dotenv
import google.generativeai as genai

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

PROMPT = (
    "You are a SOC analyst. Return a report formatted as:\n"
    "1. THREAT LEVEL: (LOW/MEDIUM/HIGH/CRITICAL)\n"
    "2. ATTACKER PROFILE: (script kiddie / APT / automated tool / unknown)\n"
    "3. SUMMARY: 3-4 sentences.\n"
    "4. RECOMMENDED ACTIONS: 3 bullet points."
)
def _get_model() -> Any:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key.startswith("your-"):
        return None
    genai.configure(api_key=api_key)
    return genai.GenerativeModel("gemini-1.5-flash", system_instruction=PROMPT)

def generate_report(commands: list[str], mitre_hits: list[dict]) -> str:
    if not commands:
        return "1. THREAT LEVEL: LOW\n2. ATTACKER PROFILE: unknown\n3. SUMMARY: Telemetry silent.\n4. RECOMMENDED ACTIONS:\n- Maintain monitoring."
    try:
        model = _get_model()
        if model is None:
            raise RuntimeError("Gemini API key is not configured")
        r = model.generate_content(f"Commands: {commands}\nMITRE: {mitre_hits}")
        return r.text.strip()
    except Exception:
        high_signal = any(any(word in command.lower() for word in ("passwd", "curl", "wget", "nmap", "chmod", "ssh", "/admin", "/wp-admin", "/.env")) for command in commands)
        level = "HIGH" if high_signal or len(commands) >= 6 else "MEDIUM"
        profile = "automated tool" if len(commands) >= 6 else "script kiddie"
        return (f"1. THREAT LEVEL: {level}\n2. ATTACKER PROFILE: {profile}\n"
                "3. SUMMARY: Command activity was captured by the Aegis honeypot. "
                "The observed sequence indicates active reconnaissance against a Linux host. "
                f"MITRE mapping identified {len(mitre_hits)} relevant technique(s).\n"
                "4. RECOMMENDED ACTIONS:\n- Block or rate-limit the source IP.\n"
                "- Preserve the session logs for investigation.\n- Review exposed services and credentials.")
