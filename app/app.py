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

EASYRSA   = "/usr/share/easy-rsa/easyrsa"
MAX_CLIENTS = 20

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────

def make_job() -> tuple[str, dict]:
    jid = f"job-{uuid.uuid4().hex[:8]}"
    status: dict = {
        "state": "running", "progress": 0, "message": "Starte...",
        "encrypt_key": True, "clients": [],
        "server_zip": None, "client_zip": None,
    }
    with JOBS_LOCK:
        JOBS[jid] = status
    return jid, status


def set_status(status: dict, progress: int, message: str) -> None:
    status["progress"] = progress
    status["message"]  = message


def run(cmd: list, env: dict | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
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
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%&*-_+" for c in pwd)):
            return pwd


def sanitize_client(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "", name)[:32] or "client"


def parse_network(cidr: str) -> tuple[str, str] | None:
    try:
        net = ipaddress.IPv4Network(cidr.strip(), strict=False)
        return str(net.network_address), str(net.netmask)
    except ValueError:
        return None


def parse_vpn_subnet(cidr: str) -> tuple[str, str, str] | None:
    """Returns (net_addr, netmask, cidr_str) – strict=True for clean subnets."""
    try:
        net = ipaddress.IPv4Network(cidr.strip(), strict=True)
        return str(net.network_address), str(net.netmask), str(net)
    except ValueError:
        return None


def validate_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", host))


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def pki_env(pki_dir: Path, cert_days: int) -> dict:
    return {
        **os.environ,
        "EASYRSA_PKI":     str(pki_dir),
        "EASYRSA_BATCH":   "1",
        "EASYRSA_CA_EXPIRE":   str(cert_days * 3),
        "EASYRSA_CERT_EXPIRE": str(cert_days),
        "EASYRSA_KEY_SIZE": "2048",
        "EASYRSA_DIGEST":  "sha512",
    }


def write_vars(pki_dir: Path, cert_days: int) -> None:
    (pki_dir / "vars").write_text(
        f'set_var EASYRSA_KEY_SIZE    "2048"\n'
        f'set_var EASYRSA_CA_EXPIRE   "{cert_days * 3}"\n'
        f'set_var EASYRSA_CERT_EXPIRE "{cert_days}"\n'
        f'set_var EASYRSA_DIGEST      "sha512"\n'
    )


def extract_first_cert(pem: str) -> str:
    m = re.search(r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
                  pem, re.DOTALL)
    return m.group(1) if m else pem.strip()


# ── Config builders ───────────────────────────────────────────────────────────

def _readme(vpn_cidr: str, use_crl: bool, server_os: str = "linux") -> str:
    crl_note_linux = (
        "\nZertifikat widerrufen:\n"
        "   easyrsa revoke <clientname> && easyrsa gen-crl\n"
        "   cp pki/crl.pem /etc/openvpn/crl.pem\n"
        if use_crl else ""
    )
    crl_note_windows = (
        "\nZertifikat widerrufen:\n"
        "   easyrsa revoke <clientname> && easyrsa gen-crl\n"
        '   crl.pem nach C:\\Program Files\\OpenVPN\\config\\ kopieren\n'
        if use_crl else ""
    )

    if server_os == "windows":
        crl_copy = '   crl.pem nach C:\\Program Files\\OpenVPN\\config\\ kopieren\n' if use_crl else ""
        return (
            "OpenVPN Server – Schnellstart (Windows)\n"
            "=========================================\n\n"
            "1. OpenVPN installieren\n"
            "   https://openvpn.net/community-downloads/\n\n"
            "2. Dateien nach C:\\Program Files\\OpenVPN\\config\\ kopieren\n"
            "   server.ovpn\n"
            + crl_copy +
            "\n3. IP-Routing aktivieren (als Administrator)\n"
            "   reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
            " /v IPEnableRouter /t REG_DWORD /d 1 /f\n\n"
            "4. NAT einrichten (PowerShell als Administrator)\n"
            f"   New-NetNat -Name VpnNat -InternalIPInterfaceAddressPrefix {vpn_cidr}\n\n"
            "5. OpenVPN-Dienst starten\n"
            "   net start OpenVPNService\n"
            "   (Autostart: Dienste → OpenVPN Service → Automatisch)\n\n"
            "6. Firewall: VPN-Port freigeben\n"
            + crl_note_windows
        )

    crl_copy = "   cp crl.pem /etc/openvpn/\n" if use_crl else ""
    return (
        "OpenVPN Server – Schnellstart (Linux)\n"
        "======================================\n\n"
        "1. OpenVPN installieren\n"
        "   Ubuntu/Debian: apt install openvpn\n"
        "   Alpine:        apk add openvpn\n\n"
        "2. Dateien nach /etc/openvpn/ kopieren\n"
        "   cp server.ovpn /etc/openvpn/server.conf\n"
        + crl_copy +
        "\n3. IP-Forwarding aktivieren\n"
        "   echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p\n\n"
        "4. NAT (eth0 ggf. anpassen)\n"
        f"   iptables -t nat -A POSTROUTING -s {vpn_cidr} -o eth0 -j MASQUERADE\n\n"
        "5. OpenVPN starten\n"
        "   systemctl enable --now openvpn@server\n\n"
        "6. Firewall: VPN-Port freigeben\n"
        + crl_note_linux
    )


def _client_readme(name: str, client_os: str, encrypt_key: bool, password: str | None) -> str:
    pwd_section = (
        f"\n3. Schlüssel-Passwort\n"
        f"   Bei der Verbindung wird das Passwort für den privaten Schlüssel abgefragt.\n"
        f"   Passwort: {password}\n"
        if (encrypt_key and password) else ""
    )
    next_step = 4 if (encrypt_key and password) else 3

    if client_os == "windows":
        return (
            f"OpenVPN Client – Installation (Windows)\n"
            f"========================================\n\n"
            f"1. OpenVPN GUI installieren\n"
            f"   https://openvpn.net/community-downloads/\n\n"
            f"2. Konfiguration importieren\n"
            f"   {name}.ovpn doppelklicken\n"
            f"   Oder: OpenVPN GUI → Datei → Profil importieren\n"
            + pwd_section +
            f"\n{next_step}. Verbinden\n"
            f"   OpenVPN GUI in der Taskleiste → Verbinden\n"
        )

    if client_os == "android":
        return (
            f"OpenVPN Client – Installation (Android / iOS)\n"
            f"==============================================\n\n"
            f"1. App installieren\n"
            f"   Android: OpenVPN for Android oder OpenVPN Connect (Play Store)\n"
            f"   iOS:     OpenVPN Connect (App Store)\n\n"
            f"2. Profil importieren\n"
            f"   {name}.ovpn per E-Mail, AirDrop oder QR-Code übertragen\n"
            f"   In der App öffnen → Importieren\n"
            + pwd_section +
            f"\n{next_step}. Verbinden\n"
            f"   App öffnen → Profil auswählen → Verbinden\n"
        )

    if client_os == "macos":
        return (
            f"OpenVPN Client – Installation (macOS)\n"
            f"======================================\n\n"
            f"1. Tunnelblick oder OpenVPN Connect installieren\n"
            f"   Tunnelblick:     https://tunnelblick.net/\n"
            f"   OpenVPN Connect: App Store\n\n"
            f"2. Konfiguration importieren\n"
            f"   {name}.ovpn doppelklicken – Tunnelblick öffnet automatisch\n"
            + pwd_section +
            f"\n{next_step}. Verbinden\n"
            f"   Tunnelblick-Symbol in der Menüleiste → {name} → Verbinden\n"
        )

    # linux (default)
    return (
        f"OpenVPN Client – Installation (Linux)\n"
        f"======================================\n\n"
        f"1. OpenVPN installieren\n"
        f"   Ubuntu/Debian: apt install openvpn\n"
        f"   Alpine:        apk add openvpn\n\n"
        f"2. Konfiguration importieren\n"
        f"   cp {name}.ovpn /etc/openvpn/client.conf\n"
        f"   Oder mit NetworkManager:\n"
        f"   nmcli connection import type openvpn file {name}.ovpn\n"
        + pwd_section +
        f"\n{next_step}. Verbinden\n"
        f"   systemctl start openvpn@client\n"
        f"   Oder: nmcli connection up {name}\n"
    )


def build_server_conf(
    server_ip, port, proto, pki_dir,
    target_net=None, redirect_gw=True,
    dns1="8.8.8.8", dns2="1.1.1.1",
    vpn_net="10.8.0.0", vpn_mask="255.255.255.0",
    client_to_client=False, max_clients=0, duplicate_cn=False,
    keepalive_ping=10, keepalive_timeout=120,
    compress=None, use_crl=False,
    server_os="linux",
) -> str:
    ca   = (pki_dir / "ca.crt").read_text().strip()
    cert = extract_first_cert((pki_dir / "issued" / "server.crt").read_text())
    key  = (pki_dir / "private" / "server.key").read_text().strip()
    ta   = (pki_dir / "ta.key").read_text().strip()

    exit_notify = "explicit-exit-notify 1" if proto == "udp" else ""

    routing: list[str] = []
    if redirect_gw:
        routing.append('push "redirect-gateway def1 bypass-dhcp"')
        if dns1: routing.append(f'push "dhcp-option DNS {dns1}"')
        if dns2: routing.append(f'push "dhcp-option DNS {dns2}"')
    if target_net:
        routing.append(f'push "route {target_net[0]} {target_net[1]}"')
    routing_block = "\n".join(routing) if routing else "# kein Routing konfiguriert"

    extras: list[str] = []
    if client_to_client:  extras.append("client-to-client")
    if max_clients > 0:   extras.append(f"max-clients {max_clients}")
    if duplicate_cn:      extras.append("duplicate-cn")
    if use_crl:           extras.append("crl-verify /etc/openvpn/crl.pem")
    if compress and compress != "none":
        extras += [f"compress {compress}", f'push "compress {compress}"']
    extras_block = "\n".join(extras)

    user_group = "user nobody\ngroup nogroup\n" if server_os == "linux" else ""

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

topology subnet
server {vpn_net} {vpn_mask}
{routing_block}

keepalive {keepalive_ping} {keepalive_timeout}
persist-key
persist-tun

{user_group}
{extras_block}

status openvpn-status.log
log-append openvpn.log
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


def build_client_ovpn(server_ip, port, proto, pki_dir,
                      client_name: str, compress=None, client_os="linux") -> str:
    ca   = (pki_dir / "ca.crt").read_text().strip()
    cert = extract_first_cert(
        (pki_dir / "issued" / f"{client_name}.crt").read_text()
    )
    key  = (pki_dir / "private" / f"{client_name}.key").read_text().strip()
    ta   = (pki_dir / "ta.key").read_text().strip()

    exit_notify   = "explicit-exit-notify 1" if proto == "udp" else ""
    compress_line = f"compress {compress}" if (compress and compress != "none") else ""

    # persist-tun causes reconnect issues on mobile (system kills tun on network change)
    persist_tun   = "" if client_os in ("android", "ios") else "persist-tun"
    # Windows needs these to prevent DNS leaks and for reliable routing
    platform_block = "block-outside-dns\nroute-method exe" if client_os == "windows" else ""

    return f"""\
# Generated by OpenVPN Web Config Generator
client
dev tun
proto {proto}
remote {server_ip} {port}
resolv-retry infinite
nobind
persist-key
{persist_tun}

data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
auth SHA512
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
remote-cert-tls server

{platform_block}
{compress_line}
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

def generate_vpn(
    jid: str, server_ip: str, port: int, proto: str,
    clients: list[str], cert_days: int,
    target_net=None, redirect_gw=True, encrypt_key=True,
    dns1="8.8.8.8", dns2="1.1.1.1",
    vpn_net="10.8.0.0", vpn_mask="255.255.255.0", vpn_cidr="10.8.0.0/24",
    client_to_client=False, max_clients=0, duplicate_cn=False,
    keepalive_ping=10, keepalive_timeout=120,
    compress=None, use_crl=False,
    server_os="linux", client_oses=None,
) -> None:
    if client_oses is None:
        client_oses = ["linux"] * len(clients)
    status  = JOBS[jid]
    job_dir = BASE_JOBS_DIR / jid
    job_dir.mkdir(parents=True, exist_ok=True)
    pki_dir = job_dir / "pki"

    try:
        env = pki_env(pki_dir, cert_days)

        set_status(status, 5,  "Initialisiere PKI …")
        run([EASYRSA, "--batch", "init-pki"], env=env)
        write_vars(pki_dir, cert_days)

        set_status(status, 15, "Erstelle CA …")
        ca_env = {**env, "EASYRSA_REQ_CN": f"ca-{jid[:8]}"}
        run([EASYRSA, "--batch", "build-ca", "nopass"], env=ca_env)
        if not (pki_dir / "ca.crt").exists():
            raise RuntimeError("CA-Zertifikat nicht erstellt")

        set_status(status, 28, "Erstelle Server-Zertifikat …")
        run([EASYRSA, "--batch", "build-server-full", "server", "nopass"], env=env)

        set_status(status, 40, "Erstelle TLS-Crypt-Schlüssel …")
        ta_key = str(pki_dir / "ta.key")
        try:
            run(["openvpn", "--genkey", "tls-crypt", ta_key])
        except RuntimeError:
            run(["openvpn", "--genkey", "--secret", ta_key])

        # ── Client certs ──────────────────────────────────────────────────────
        client_results: list[dict] = []
        n = len(clients)
        for i, name in enumerate(clients):
            cos = client_oses[i] if i < len(client_oses) else "linux"
            pct = 50 + int(i / n * 30)
            set_status(status, pct, f"Client '{name}' ({i+1}/{n}) …")
            if encrypt_key:
                password = generate_password()
                client_env = {**env, "EASYRSA_PASSOUT": f"pass:{password}"}
                run([EASYRSA, "--batch", "build-client-full", name], env=client_env)
            else:
                password = None
                run([EASYRSA, "--batch", "build-client-full", name, "nopass"], env=env)
            readme_file = f"{name}_install_readme.txt"
            (job_dir / readme_file).write_text(
                _client_readme(name, cos, encrypt_key, password)
            )
            client_results.append({
                "name":     name,
                "password": password,
                "ovpn":     f"{jid}/{name}.ovpn",
                "readme":   f"{jid}/{readme_file}",
                "os":       cos,
            })

        # ── CRL ───────────────────────────────────────────────────────────────
        if use_crl:
            set_status(status, 82, "Erstelle CRL …")
            run([EASYRSA, "--batch", "gen-crl"], env=env)

        # ── Configs ───────────────────────────────────────────────────────────
        set_status(status, 86, "Erzeuge Konfigurationsdateien …")
        server_conf = build_server_conf(
            server_ip, port, proto, pki_dir,
            target_net, redirect_gw,
            dns1, dns2, vpn_net, vpn_mask,
            client_to_client, max_clients, duplicate_cn,
            keepalive_ping, keepalive_timeout,
            compress, use_crl, server_os,
        )

        ovpn_map: dict[str, str] = {}
        for cr in client_results:
            ovpn = build_client_ovpn(
                server_ip, port, proto, pki_dir,
                cr["name"], compress, cr["os"],
            )
            (job_dir / f"{cr['name']}.ovpn").write_text(ovpn)
            ovpn_map[cr["name"]] = ovpn

        # ── Server files ──────────────────────────────────────────────────────
        set_status(status, 93, "Packe Archive …")
        (job_dir / "server.ovpn").write_text(server_conf)
        (job_dir / "install_readme.txt").write_text(_readme(vpn_cidr, use_crl, server_os))
        server_crl_key = None
        if use_crl:
            crl_src = pki_dir / "crl.pem"
            if crl_src.exists():
                (job_dir / "crl.pem").write_bytes(crl_src.read_bytes())
                server_crl_key = f"{jid}/crl.pem"

        # ── All-clients ZIP ───────────────────────────────────────────────────
        client_zip = job_dir / "alle-clients.zip"
        with zipfile.ZipFile(client_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for cr in client_results:
                zf.writestr(f"{cr['name']}.ovpn", ovpn_map[cr["name"]])
                readme_path = job_dir / f"{cr['name']}_install_readme.txt"
                if readme_path.exists():
                    zf.write(readme_path, f"{cr['name']}_install_readme.txt")
            if encrypt_key:
                creds = "".join(
                    f"Client:             {c['name']}\n"
                    f"Schlüssel-Passwort: {c['password']}\n\n"
                    for c in client_results
                )
                zf.writestr("zugangsdaten.txt", creds)

        status.update({
            "state": "done", "progress": 100,
            "message": "VPN-Konfiguration bereit!",
            "encrypt_key":   encrypt_key,
            "clients":       client_results,
            "server_ovpn":   f"{jid}/server.ovpn",
            "server_readme": f"{jid}/install_readme.txt",
            "server_crl":    server_crl_key,
            "client_zip":    f"{jid}/alle-clients.zip",
        })

    except Exception as exc:
        status.update({"state": "error", "message": str(exc)})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/create", methods=["POST"])
def create():
    f = request.form

    server_ip = f.get("server_ip", "").strip()
    port_raw  = f.get("port", "1194").strip()
    proto     = f.get("proto", "udp").strip()
    days_raw  = f.get("days", "365").strip()

    # Clients
    clients = list(dict.fromkeys(
        sanitize_client(c) for c in f.getlist("clients[]") if c.strip()
    ))[:MAX_CLIENTS] or ["client"]

    # Toggles
    redirect_gw   = f.get("redirect_gw")   == "on"
    encrypt_key   = f.get("encrypt_key")   == "on"
    client_to_client = f.get("client_to_client") == "on"
    duplicate_cn     = f.get("duplicate_cn")     == "on"
    use_crl          = f.get("use_crl")          == "on"

    # DNS
    dns1 = f.get("dns1", "8.8.8.8").strip() or "8.8.8.8"
    dns2 = f.get("dns2", "1.1.1.1").strip()

    # VPN subnet
    vpn_subnet_raw = f.get("vpn_subnet", "10.8.0.0/24").strip() or "10.8.0.0/24"

    # Numeric fields
    target_net_raw      = f.get("target_net", "").strip()
    max_clients_raw     = f.get("max_clients", "0").strip()
    keepalive_ping_raw  = f.get("keepalive_ping",    "10").strip()
    keepalive_timeout_raw = f.get("keepalive_timeout", "120").strip()
    compress = f.get("compress", "none").strip()

    # ── Validation ───────────────────────────────────────────────────────────
    if not validate_host(server_ip):
        return jsonify({"error": "Ungültige Server-IP oder Hostname"}), 400

    try:
        port = int(port_raw); assert 1 <= port <= 65535
    except Exception:
        return jsonify({"error": "Port muss zwischen 1 und 65535 liegen"}), 400

    if proto not in ("udp", "tcp"):
        return jsonify({"error": "Protokoll muss udp oder tcp sein"}), 400

    try:
        cert_days = int(days_raw); assert 1 <= cert_days <= 3650
    except Exception:
        return jsonify({"error": "Gültigkeit: 1–3650 Tage"}), 400

    target_net = None
    if target_net_raw:
        target_net = parse_network(target_net_raw)
        if target_net is None:
            return jsonify({"error": f"Ungültiges Zielnetz '{target_net_raw}'"}), 400

    vpn_sub = parse_vpn_subnet(vpn_subnet_raw)
    if vpn_sub is None:
        return jsonify({"error": f"Ungültiges VPN-Subnetz '{vpn_subnet_raw}' — z.B. 10.8.0.0/24"}), 400
    vpn_net, vpn_mask, vpn_cidr = vpn_sub

    for ip, label in [(dns1, "DNS 1"), (dns2, "DNS 2")]:
        if ip and not validate_ip(ip):
            return jsonify({"error": f"Ungültige IP für {label}: '{ip}'"}), 400

    try:
        max_cl = int(max_clients_raw or 0); assert 0 <= max_cl <= 1000
    except Exception:
        return jsonify({"error": "Max. Verbindungen: 0–1000 (0 = unbegrenzt)"}), 400

    try:
        kp = int(keepalive_ping_raw   or 10)
        kt = int(keepalive_timeout_raw or 120)
        assert 1 <= kp <= 300 and kp < kt <= 3600
    except Exception:
        return jsonify({"error": "Keepalive: Ping 1–300 s, Timeout muss größer als Ping sein"}), 400

    if compress not in ("none", "lz4-v2"):
        compress = "none"

    server_os = f.get("server_os", "linux").strip()
    if server_os not in ("linux", "windows"):
        server_os = "linux"

    _valid_os = {"linux", "windows", "android", "macos"}
    client_oses = [
        cos if (cos := v.strip()) in _valid_os else "linux"
        for v in f.getlist("client_os[]")
    ]
    while len(client_oses) < len(clients):
        client_oses.append("linux")
    client_oses = client_oses[:len(clients)]

    jid, _ = make_job()
    threading.Thread(
        target=generate_vpn,
        args=(jid, server_ip, port, proto, clients, cert_days,
              target_net, redirect_gw, encrypt_key,
              dns1, dns2, vpn_net, vpn_mask, vpn_cidr,
              client_to_client, max_cl, duplicate_cn,
              kp, kt, compress, use_crl, server_os, client_oses),
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


# ── Cleanup jobs older than 24 h ──────────────────────────────────────────────

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
