import os
import socket
import threading
from datetime import datetime
import paramiko
from aegis.honeypot.ai_responder import generate_response
from aegis.storage import record_event

MOTD = """Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.
Last login: Thu Sep 17 19:42:10 2026 from 192.168.1.50\r\n
"""

class AegisSSHServer(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip = ip
        self.user = "unknown"
        self.event = threading.Event()
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, u, p):
        self.user = u
        return paramiko.AUTH_SUCCESSFUL
    def check_auth_none(self, u):
        self.user = u
        return paramiko.AUTH_SUCCESSFUL
    def check_channel_pty_request(self, *a): return True
    def check_channel_shell_request(self, c):
        self.event.set()
        return True

def ensure_data_directory():
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "logs.txt")
    if not os.path.exists(p):
        with open(p, "w", encoding="utf-8") as f: pass
    return p

def log_cmd(p, ip, u, cmd):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean = cmd.strip().replace("\r", "").replace("\n", "")
    with open(p, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] | IP={ip} | USER={u} | CMD={clean}\n")
    record_event("ssh_command", ip, username=u, command=clean)

def handle_client(sock, addr, key, log_path):
    ip = addr[0]
    t = None
    try:
        t = paramiko.Transport(sock)
        t.add_server_key(key)
        srv = AegisSSHServer(ip)
        t.start_server(server=srv)
        ch = t.accept(20)
        if not ch: return
        srv.event.wait(10)
        if not srv.event.is_set(): return
        ch.send(MOTD.replace("\n", "\r\n"))
        p = f"{srv.user}@ubuntu-srv-01:~# "
        ch.send(p)
        ctx, buf = [], ""
        skip_lf = False
        while True:
            data = ch.recv(1024)
            if not data:
                break
            for byte in data:
                if byte == 10 and skip_lf:
                    skip_lf = False
                    continue
                skip_lf = False
                if byte in (13, 10):
                    if byte == 13:
                        skip_lf = True
                    cmd = buf.strip()
                    buf = ""
                    if cmd:
                        log_cmd(log_path, ip, srv.user, cmd)
                        if cmd.lower() in ["exit", "quit", "logout"]:
                            try:
                                ch.send(b"\r\nlogout\r\n")
                            except (EOFError, OSError, paramiko.SSHException):
                                pass
                            return
                        out = generate_response(cmd, ctx)
                        if out:
                            try:
                                ch.send((out.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n").encode("utf-8", errors="replace"))
                            except (EOFError, OSError, paramiko.SSHException):
                                return
                        ctx.append({"command": cmd, "output": out})
                        if len(ctx) > 10:
                            ctx.pop(0)
                    try:
                        ch.send(b"\r\n" + p.encode("utf-8"))
                    except (EOFError, OSError, paramiko.SSHException):
                        return
                elif byte in (127, 8):
                    if buf:
                        buf = buf[:-1]
                        try:
                            ch.send(b"\b \b")
                        except (EOFError, OSError, paramiko.SSHException):
                            return
                elif byte == 3:
                    try:
                        ch.send(b"^C\r\n")
                    except (EOFError, OSError, paramiko.SSHException):
                        return
                    buf = ""
                    try:
                        ch.send(p.encode("utf-8"))
                    except (EOFError, OSError, paramiko.SSHException):
                        return
                else:
                    char = bytes((byte,)).decode("utf-8", errors="ignore")
                    if char:
                        buf += char
                        try:
                            ch.send(bytes((byte,)))
                        except (EOFError, OSError, paramiko.SSHException):
                            return
    except (EOFError, OSError, paramiko.SSHException, socket.error):
        pass
    finally:
        if t: t.close()
        sock.close()

def start_honeypot(host="0.0.0.0", port=2222):
    lp = ensure_data_directory()
    key = paramiko.RSAKey.generate(2048)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        s.listen(100)
        print(f"[HONEYPOT] Bound on {host}:{port}")
        while True:
            cs, ca = s.accept()
            threading.Thread(target=handle_client, args=(cs, ca, key, lp), daemon=True).start()
    finally: s.close()

if __name__ == "__main__":
    start_honeypot()
