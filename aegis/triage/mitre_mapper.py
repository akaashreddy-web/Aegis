import json
import os
import re
from typing import Any
from dotenv import load_dotenv
import google.generativeai as genai

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

PROMPT = (
    "You are a cybersecurity analyst. Identify MITRE ATT&CK techniques from commands. "
    "Return ONLY valid JSON: [{\"technique_id\": \"T1046\", \"technique_name\": \"Scanning\", \"evidence\": \"cmd\"}]"
)
def _get_model() -> Any:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key.startswith("your-"):
        return None
    genai.configure(api_key=api_key)
    return genai.GenerativeModel("gemini-1.5-flash", system_instruction=PROMPT)

def _fallback_mapping(commands: list[str]) -> list[dict[str, str]]:
    rules = [
        (("whoami",), "T1033", "System Owner/User Discovery"),
        (("uname", "hostname", "/etc/os-release"), "T1082", "System Information Discovery"),
        (("/etc/passwd", "getent passwd"), "T1087", "Account Discovery"),
        (("curl", "wget", "invoke-webrequest"), "T1105", "Ingress Tool Transfer"),
        (("nmap", "masscan", "netstat", "ss "), "T1046", "Network Service Scanning"),
        (("find /", "ls -la", "ls -al"), "T1083", "File and Directory Discovery"),
        (("/admin", "/wp-admin", "/.env"), "T1190", "Exploit Public-Facing Application"),
    ]
    hits = []
    for command in commands:
        lowered = command.lower()
        for markers, technique_id, name in rules:
            if any(marker in lowered for marker in markers):
                hits.append({"technique_id": technique_id, "technique_name": name, "evidence": command})
                break
    return hits


def map_to_mitre(commands: list[str]) -> list[dict[str, str]]:
    cmds = list(dict.fromkeys([c.strip() for c in commands if c.strip()]))
    if not cmds:
        return []
    try:
        model = _get_model()
        if model is None:
            return _fallback_mapping(cmds)
        r = model.generate_content("Commands:\n" + "\n".join(f"- {c}" for c in cmds))
        text = re.sub(r"```(?:json)?", "", r.text or "", flags=re.IGNORECASE).replace("```", "").strip()
        match = re.search(r"\[\s*\{.*\}\s*\]", text, re.DOTALL)
        parsed = json.loads(match.group(0) if match else text)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return _fallback_mapping(cmds)
