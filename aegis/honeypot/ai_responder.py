import os
from typing import Any

from dotenv import load_dotenv
import google.generativeai as genai

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

SYSTEM_PROMPT = (
    "You are a realistic Linux bash shell on an Ubuntu 20.04 server. "
    "Respond ONLY with the terminal output the command would produce. "
    "No explanations, no markdown, no commentary. Keep responses under 3 lines."
)

def _get_model() -> Any:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key.startswith("your-"):
        return None
    genai.configure(api_key=api_key)
    return genai.GenerativeModel("gemini-1.5-flash", system_instruction=SYSTEM_PROMPT)


def _fallback_response(command: str) -> str:
    command_name = command.split(maxsplit=1)[0].lower()
    responses = {
        "whoami": "root",
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "uname": "Linux ubuntu-srv-01 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux",
        "pwd": "/root",
        "ls": "bin  etc  home  lib  opt  root  sys  usr  var",
        "hostname": "ubuntu-srv-01",
        "date": "Thu Sep 18 12:00:00 UTC 2026",
    }
    return responses.get(command_name, f"bash: {command_name}: command not found")

def generate_response(command: str, context: list) -> str:
    cmd = command.strip()
    if not cmd:
        return ""
    if cmd in ["clear", "cls"]:
        return "\033[H\033[J"
    if cmd in ["exit", "quit", "logout"]:
        return "logout\n"
    try:
        model = _get_model()
        if model is None:
            return _fallback_response(cmd)
        ctx = "Recent terminal command history:\n"
        for item in context[-5:]:
            ctx += f"$ {item.get('command', '')}\n{item.get('output', '')}\n"
        resp = model.generate_content(
            f"{ctx}\nCurrent typed command: {cmd}\nTerminal Output:",
            generation_config=genai.types.GenerationConfig(temperature=0.2, max_output_tokens=150)
        )
        out = resp.text if resp.text else ""
        if out.startswith("```"):
            lines = out.splitlines()
            out = "\n".join(lines[1:-1]) if len(lines) >= 2 and lines[-1].startswith("```") else "\n".join(lines[1:])
        return out.strip("\n\r")
    except Exception:
        return _fallback_response(cmd)
