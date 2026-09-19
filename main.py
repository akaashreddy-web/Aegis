import os
import socket
import sys
import time
import threading
from aegis.honeypot.server import start_honeypot, ensure_data_directory
from aegis.honeypot.web_server import start_web_honeypot
from aegis.storage import initialize_database


def get_local_ip() -> str:
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        if host_ip and host_ip != "127.0.0.1":
            return host_ip
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        pass

    return "127.0.0.1"


def main():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("==================================================")
    print("   AEGIS: Active Defense & Threat Triage Platform ")
    print("==================================================")
    
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("GEMINI_API_KEY=your-gemini-api-key-here\n")
    
    logs_path = ensure_data_directory()
    initialize_database()
    local_ip = get_local_ip()
    print(f"[*] Telemetry log bound to: {logs_path}")
    print(f"[*] Local network IP: {local_ip}")

    honeypot_thread = threading.Thread(
        target=start_honeypot,
        kwargs={"host": "0.0.0.0", "port": 2222},
        daemon=True
    )
    honeypot_thread.start()

    web_thread = threading.Thread(
        target=start_web_honeypot,
        kwargs={"host": "0.0.0.0", "port": 8080},
        daemon=True,
    )
    web_thread.start()

    print("[*] Honeypot server running on port 2222.")
    print(f"[*] Web honeypot running on port 8080: http://{local_ip}:8080")
    print(f"[*] Connect from another device: ssh test@{local_ip} -p 2222")
    print(f"[*] Dashboard: http://{local_ip}:8501")
    print("[*] Dashboard local command: streamlit run dashboard/app.py")
    print("==================================================")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nTerminating AEGIS.")
        sys.exit(0)

if __name__ == "__main__":
    main()