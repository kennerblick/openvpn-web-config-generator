from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import subprocess
import os
import uuid
import secrets
import string
import threading
import zipfile
import re
import ipaddress
import time
import shutil

app = Flask(__name__)

BASE_JOBS_DIR = Path("/app/jobs")
BASE_JOBS_DIR.mkdir(parents=True, exist_ok=True)

EASYRSA = "/usr/share/easy-rsa/easyrsa"

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────

def make_job() -> tuple[str, dict]:
    jid = f"job-{uuid.uuid4().hex[:8]}"
    status = {
        "state": "running",
        "progress": 0,
        "message": "Starte...",
        "username": None,
        "password": None,
        "server_zip": None,
        "client_zip": None,
        "client_ovpn": None,
    }
    with JOBS_LOCK:
        JOBS[jid] = status
    return jid, status


def set_status(status: dict, progress: int, message: str) -> None:
    status["progress"] = progress
    status["message"] = message


def run(cmd: list, env: dict | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        # easy-rsa writes errors to stdout, not stderr
        combined = (result.stdout + "\n" + result.stderr).strip()
        raise RuntimeError(
            f"{' '.join(str(c) for c in cmd)}\n\n"
            f"{combined[-2000:] or '(keine Ausgabe)'}"
        )
    return result


def generate_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%&*-_+"
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        if (
            any(c.isupper() for c in pwd)
            and any(c.islower() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%&*-_+" for c in pwd)
        ):
            return pwd


def generate_username() -> str:
    adj = ["fast", "dark", "cold", "blue", "wild", "free", "stark", "calm"]
    noun = ["wolf", "hawk", "bear", "fox", "lynx", "crow", "pike", "oaks"]
    num = secrets.randbelow(900) + 100
    return f"{secrets.choice(adj)}{secrets.choice(noun)}{num}"


def sanitize_client(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "", name)[:32]
    return cleaned or "client"


def parse_network(cidr: str) -> tuple[str, str] | None:
    """Parse '192.168.1.0/24' → ('192.168.1.0', '255.255.255.0'), or None if invalid."""
    try:
        net = ipaddress.IPv4Network(cidr.strip(), strict=False)
        return str(net.network_address), str(net.netmask)
    except ValueError:
        return None


def validate_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", host))


def pki_env(pki_dir: Path, cert_days: int) -> dict:
    """Base env — no EASYRSA_REQ_CN (conflicts with build-server/client-full)."""
    return {
        **os.environ,
        "EASYRSA_PKI": str(pki_dir),
        "EASYRSA_BATCH": "1",
        "EASYRSA_CA_EXPIRE": str(cert_days * 3),
        "EASYRSA_CERT_EXPIRE": str(cert_days),
        "EASYRSA_KEY_SIZE": "2048",
        "EASYRSA_DIGEST": "sha512",
    }


def write_vars(pki_dir: Path, cert_days: int) -> None:
    """Write vars file that easy-rsa expects inside the PKI directory."""
    (pki_dir / "vars").write_text(
        f'set_var EASYRSA_KEY_SIZE    "2048"\n'
        f'set_var EASYRSA_CA_EXPIRE   "{cert_days * 3}"\n'
        f'set_var EASYRSA_CERT_EXPIRE "{cert_days}"\n'
        f'set_var EASYRSA_DIGEST      "sha512"\n'
    )


def extract_first_cert(pem: str) -> str:
    """Return only the first -----BEGIN CERTIFICATE----- block."""
    match = re.search(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        pem,
        re.DOTALL,
    )
    return match.group(1) if match else pem.strip()


# ── Config builders ───────────────────────────────────────────────────────────

_CHECKPWD = """#!/bin/sh
# OpenVPN user/password verification — called via-env by OpenVPN
PASSFILE="/etc/openvpn/userpass.txt"
if grep -qxF "${username}:${password}" "$PASSFILE" 2>/dev/null; then
    exit 0
fi
exit 1
"""

_README = """\
OpenVPN Server – Schnellstart
==============================

1. OpenVPN installieren
   Ubuntu/Debian:  apt install openvpn
   CentOS/RHEL:    dnf install openvpn
   Alpine:         apk add openvpn

2. Dateien nach /etc/openvpn/ kopieren
   cp server.conf  /etc/openvpn/
   cp userpass.txt /etc/openvpn/
   cp checkpwd.sh  /etc/openvpn/
   chmod 700       /etc/openvpn/checkpwd.sh
   chmod 600       /etc/openvpn/userpass.txt

3. IP-Forwarding aktivieren
   echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf && sysctl -p

4. NAT einrichten (eth0 ggf. anpassen)
   iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

5. OpenVPN starten
   systemctl enable --now openvpn@server
   # oder: openvpn --config /etc/openvpn/server.conf

6. Firewall: UDP-Port (oder TCP) in der Firewall freigeben.

Hinweis: user/group im server.conf sind auf nobody/nogroup gesetzt
(Ubuntu/Debian). Auf Alpine: nobody/nobody.
"""


def build_server_conf(server_ip, port, proto, pki_dir,
                      target_net: tuple[str, str] | None = None,
                      redirect_gw: bool = True) -> str:
    ca = (pki_dir / "ca.crt").read_text().strip()
    cert = extract_first_cert((pki_dir / "issued" / "server.crt").read_text())
    key = (pki_dir / "private" / "server.key").read_text().strip()
    ta = (pki_dir / "ta.key").read_text().strip()

    exit_notify = "explicit-exit-notify 1" if proto == "udp" else ""

    routing_lines: list[str] = []
    if redirect_gw:
        routing_lines += [
            'push "redirect-gateway def1 bypass-dhcp"',
            'push "dhcp-option DNS 8.8.8.8"',
            'push "dhcp-option DNS 1.1.1.1"',
        ]
    if target_net:
        net_addr, net_mask = target_net
        routing_lines.append(f'push "route {net_addr} {net_mask}"')
    routing = "\n".join(routing_lines) if routing_lines else "# kein Routing konfiguriert"

    return f"""\
# Generated by OpenVPN Web Config Generator
port {port}
proto {proto}
dev tun

dh none

data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
auth SHA512
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

server 10.8.0.0 255.255.255.0
{routing}

keepalive 10 120
persist-key
persist-tun

user nobody
group nogroup

auth-user-pass-verify /etc/openvpn/checkpwd.sh via-env
script-security 2

status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3
{exit_notify}

<ca>
{ca}
</ca>
<cert>
{cert}
</cert>
<key>
{key}
</key>
<tls-crypt>
{ta}
</tls-crypt>
"""


def build_client_ovpn(server_ip, port, proto, pki_dir, client_name) -> str:
    ca = (pki_dir / "ca.crt").read_text().strip()
    cert = extract_first_cert(
        (pki_dir / "issued" / f"{client_name}.crt").read_text()
    )
    key = (pki_dir / "private" / f"{client_name}.key").read_text().strip()
    ta = (pki_dir / "ta.key").read_text().strip()

    exit_notify = "explicit-exit-notify 1" if proto == "udp" else ""

    return f"""\
# Generated by OpenVPN Web Config Generator
client
dev tun
proto {proto}
remote {server_ip} {port}
resolv-retry infinite
nobind
persist-key
persist-tun

data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
auth SHA512
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
remote-cert-tls server

auth-user-pass
verb 3
{exit_notify}

<ca>
{ca}
</ca>
<cert>
{cert}
</cert>
<key>
{key}
</key>
<tls-crypt>
{ta}
</tls-crypt>
"""


# ── Generation worker ─────────────────────────────────────────────────────────

def generate_vpn(jid: str, server_ip: str, port: int, proto: str,
                 client_name: str, cert_days: int,
                 target_net: tuple[str, str] | None = None,
                 redirect_gw: bool = True) -> None:
    status = JOBS[jid]
    job_dir = BASE_JOBS_DIR / jid
    job_dir.mkdir(parents=True, exist_ok=True)
    pki_dir = job_dir / "pki"
    # Do NOT pre-create pki_dir — let easyrsa init-pki create it

    try:
        env = pki_env(pki_dir, cert_days)

        set_status(status, 10, "Initialisiere PKI …")
        run([EASYRSA, "--batch", "init-pki"], env=env)
        write_vars(pki_dir, cert_days)

        set_status(status, 20, "Erstelle CA …")
        # EASYRSA_REQ_CN only for build-ca; forbidden in build-server/client-full
        ca_env = {**env, "EASYRSA_REQ_CN": f"ca-{jid[:8]}"}
        run([EASYRSA, "--batch", "build-ca", "nopass"], env=ca_env)
        if not (pki_dir / "ca.crt").exists():
            raise RuntimeError("CA-Zertifikat nicht erstellt — easy-rsa Fehler")

        set_status(status, 40, "Erstelle Server-Zertifikat …")
        run([EASYRSA, "--batch", "build-server-full", "server", "nopass"], env=env)

        set_status(status, 55, "Erstelle TLS-Crypt-Schlüssel …")
        ta_key = str(pki_dir / "ta.key")
        try:
            run(["openvpn", "--genkey", "tls-crypt", ta_key])   # OpenVPN 2.6+
        except RuntimeError:
            run(["openvpn", "--genkey", "--secret", ta_key])    # OpenVPN 2.4/2.5

        set_status(status, 70, f"Erstelle Client-Zertifikat ({client_name}) …")
        run([EASYRSA, "--batch", "build-client-full", client_name, "nopass"], env=env)

        set_status(status, 82, "Generiere Zugangsdaten …")
        username = generate_username()
        password = generate_password()

        set_status(status, 90, "Erzeuge Konfigurationsdateien …")
        server_conf = build_server_conf(server_ip, port, proto, pki_dir, target_net, redirect_gw)
        client_ovpn = build_client_ovpn(server_ip, port, proto, pki_dir, client_name)
        userpass_txt = f"{username}:{password}\n"
        creds_txt = f"Benutzername: {username}\nPasswort:     {password}\n"

        set_status(status, 95, "Packe Archive …")

        server_zip_path = job_dir / "server-bundle.zip"
        with zipfile.ZipFile(server_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("server.conf", server_conf)
            zf.writestr("userpass.txt", userpass_txt)
            zf.writestr("checkpwd.sh", _CHECKPWD)
            zf.writestr("README.txt", _README)

        client_zip_path = job_dir / f"{client_name}-client.zip"
        with zipfile.ZipFile(client_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{client_name}.ovpn", client_ovpn)
            zf.writestr("credentials.txt", creds_txt)

        ovpn_path = job_dir / f"{client_name}.ovpn"
        ovpn_path.write_text(client_ovpn)

        status.update({
            "state": "done",
            "progress": 100,
            "message": "VPN-Konfiguration bereit!",
            "username": username,
            "password": password,
            "server_zip": f"{jid}/server-bundle.zip",
            "client_zip": f"{jid}/{client_name}-client.zip",
            "client_ovpn": f"{jid}/{client_name}.ovpn",
        })

    except Exception as exc:
        status.update({
            "state": "error",
            "message": str(exc),
        })


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/create", methods=["POST"])
def create():
    server_ip = request.form.get("server_ip", "").strip()
    port_raw = request.form.get("port", "1194").strip()
    proto = request.form.get("proto", "udp").strip()
    client = sanitize_client(request.form.get("client", "client"))
    days_raw = request.form.get("days", "365").strip()
    target_net_raw = request.form.get("target_net", "").strip()

    if not validate_host(server_ip):
        return jsonify({"error": "Ungültige Server-IP oder Hostname"}), 400

    try:
        port = int(port_raw)
        assert 1 <= port <= 65535
    except (ValueError, AssertionError):
        return jsonify({"error": "Port muss zwischen 1 und 65535 liegen"}), 400

    if proto not in ("udp", "tcp"):
        return jsonify({"error": "Protokoll muss udp oder tcp sein"}), 400

    try:
        cert_days = int(days_raw)
        assert 1 <= cert_days <= 3650
    except (ValueError, AssertionError):
        return jsonify({"error": "Gültigkeit: 1–3650 Tage"}), 400

    target_net = None
    if target_net_raw:
        target_net = parse_network(target_net_raw)
        if target_net is None:
            return jsonify({"error": f"Ungültiges Zielnetz: '{target_net_raw}' (erwartet z.B. 192.168.10.0/24)"}), 400

    redirect_gw = request.form.get("redirect_gw") == "on"

    jid, _ = make_job()
    threading.Thread(
        target=generate_vpn,
        args=(jid, server_ip, port, proto, client, cert_days, target_net, redirect_gw),
        daemon=True,
    ).start()

    return jsonify({"job_id": jid})


@app.route("/status/<job_id>")
def status(job_id):
    with JOBS_LOCK:
        if job_id not in JOBS:
            return jsonify({"error": "Job nicht gefunden"}), 404
        return jsonify(JOBS[job_id])


@app.route("/download/<path:filepath>")
def download(filepath):
    try:
        full = (BASE_JOBS_DIR / filepath).resolve()
        base = BASE_JOBS_DIR.resolve()
        if not str(full).startswith(str(base) + os.sep):
            return "Zugriff verweigert", 403
        if not full.exists():
            return "Datei nicht gefunden", 404
        return send_file(full, as_attachment=True)
    except Exception:
        return "Ungültiger Pfad", 400


# ── Background cleanup (remove jobs older than 24 h) ─────────────────────────

def _cleanup() -> None:
    while True:
        time.sleep(3600)
        cutoff = time.time() - 86400
        for d in BASE_JOBS_DIR.iterdir():
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
                with JOBS_LOCK:
                    JOBS.pop(d.name, None)


threading.Thread(target=_cleanup, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9192, threaded=True)
