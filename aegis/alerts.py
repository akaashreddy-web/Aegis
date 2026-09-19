import json
import os
import threading
import urllib.request

from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))


def dispatch_alert(event: dict[str, str]) -> None:
    """Send an optional webhook alert without blocking honeypot request handling."""
    webhook_url = os.getenv("AEGIS_ALERT_WEBHOOK_URL", "").strip()
    if not webhook_url or event.get("severity") not in {"HIGH", "CRITICAL"}:
        return
    thread = threading.Thread(target=_send_webhook, args=(webhook_url, event), daemon=True)
    thread.start()


def _send_webhook(webhook_url: str, event: dict[str, str]) -> None:
    payload = {
        "content": (
            f"AEGIS {event.get('severity')} alert: {event.get('event_type')} "
            f"from {event.get('source_ip')} on {event.get('path') or event.get('command')}"
        ),
        "aegis": event,
    }
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Aegis-Alert/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=3):
            return
    except (OSError, ValueError):
        return
