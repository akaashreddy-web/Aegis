import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from aegis.storage import record_event


class DecoyRequestHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    sys_version = "Ubuntu"

    def _record(self, method: str, path: str, details: str = "") -> None:
        record_event(
            "web_request",
            self.client_address[0],
            method=method,
            path=path[:500],
            user_agent=self.headers.get("User-Agent", "")[:500],
            details=details[:1000],
        )

    def _send_html(self, body: str, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        request_path = urlsplit(self.path).path
        self._record("GET", self.path)
        if request_path in {"/", "/index.html"}:
            self._send_html(
                """<!doctype html><html><head><title>Ubuntu Server Portal</title>
                <style>body{background:#07101c;color:#d5f9ff;font:16px monospace;max-width:760px;margin:7rem auto;padding:2rem}
                h1{color:#00f0ff}form{border:1px solid #24475a;padding:1rem}input,button{padding:.65rem;margin:.3rem;background:#0b1d2a;color:#d5f9ff;border:1px solid #00f0ff}</style>
                </head><body><h1>Ubuntu Server Portal</h1><p>Internal administration console</p>
                <form method="post" action="/login"><label>Username <input name="username"></label><br>
                <label>Password <input name="password" type="password"></label><br><button>Sign in</button></form></body></html>"""
            )
            return
        self._send_html("<h1>404 Not Found</h1>", 404)

    def do_POST(self) -> None:
        request_path = urlsplit(self.path).path
        length = min(int(self.headers.get("Content-Length", "0") or 0), 4096)
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = parse_qs(raw_body, keep_blank_values=True)
        safe_details = ", ".join(f"{key}={html.escape(values[0][:200])}" for key, values in fields.items())
        self._record("POST", self.path, safe_details)
        self._send_html("<h1>Authentication failed</h1><p>Please try again.</p>", 401)

    def log_message(self, format: str, *args: object) -> None:
        return


def start_web_honeypot(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), DecoyRequestHandler)
    print(f"[WEB HONEYPOT] Bound on {host}:{port}")
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    start_web_honeypot()
