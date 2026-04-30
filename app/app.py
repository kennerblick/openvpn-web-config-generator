from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import subprocess
import os
import uuid
import secrets
import string

app = Flask(__name__)

# Basisverzeichnis für alle Jobs
BASE_JOBS_DIR = Path("/app/jobs")
BASE_JOBS_DIR.mkdir(parents=True, exist_ok=True)

# Globaler Status (ein Job gleichzeitig)
JOB_STATUS = {
    "state": "idle",        # idle | running | done | error
    "progress": 0,
    "message": "",
    "server_conf": None,
    "client_ovpn": None,
    "cert_password": None
}

# ---------------- Hilfsfunktionen ----------------

def update(progress, message):
    JOB_STATUS.update({
        "state": "running",
        "progress": progress,
        "message": message
    })

def generate_cert_password(length=12):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+"

    pwd = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special)
    ]

    all_chars = upper + lower + digits + special
    pwd += [secrets.choice(all_chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

# ---------------- Routes ----------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/create", methods=["POST"])
def create():
    try:
        # ---- Eingaben ----
        server_ip = request.form["server_ip"]
        port = request.form.get("port", "1194")
        proto = request.form.get("proto", "udp")
        client = request.form.get("client", "clientname")

        # ---- Job-Struktur ----
        job_id = f"job-{uuid.uuid4().hex[:6]}"
        job_dir = BASE_JOBS_DIR / job_id
        ovpn_dir = job_dir / "openvpn"
        ovpn_dir.mkdir(parents=True)

        cert_password = generate_cert_password()

        # ---- Umgebung für kylemanna/openvpn ----
        env = os.environ.copy()
        env["OPENVPN"] = str(ovpn_dir)
        env["EASYRSA_BATCH"] = "1"
        env["EASYRSA_REQ_CN"] = "job-ca"

        # ---- Step 1: Server-Konfiguration ----
        update(20, "Erzeuge Server-Konfiguration")

        subprocess.run(
            [
                "ovpn_genconfig",
                "-u", f"{proto}://{server_ip}:{port}",
                "-C", "AES-256-GCM",
                "-a", "SHA512",
                "-c"
            ],
            env=env,
            check=True
        )

        # ---- openvpn.conf → server.conf ----
        openvpn_conf = ovpn_dir / "openvpn.conf"
        server_conf = ovpn_dir / "server.conf"

        if not openvpn_conf.exists():
            raise RuntimeError("openvpn.conf wurde nicht erzeugt")

        openvpn_conf.rename(server_conf)

        # ---- Step 2: PKI (CA ohne Passwort) ----
        update(40, "Initialisiere einmalige Job-PKI")

        subprocess.run(
            ["ovpn_initpki", "nopass"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )

        # ---- Step 3: Client-Zertifikat MIT Passwort ----
        update(70, "Erzeuge Client-Zertifikat (geschützt)")

        cmd = (
            f"printf '%s\n%s\n' '{cert_password}' '{cert_password}' | "
            f"easyrsa build-client-full {client} pass"
        )

        subprocess.run(
            cmd,
            shell=True,
            env=env,
            cwd=ovpn_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )

        # ---- Step 4: Client-.ovpn erzeugen ----
        client_ovpn = job_dir / f"{client}.ovpn"

        subprocess.run(
            f"ovpn_getclient {client} > {client_ovpn}",
            shell=True,
            env=env,
            check=True
        )

        if not client_ovpn.exists():
            raise RuntimeError("client.ovpn wurde nicht erzeugt")

        # ---- Fertig ----
        JOB_STATUS.update({
            "state": "done",
            "progress": 100,
            "message": "VPN-Konfiguration fertig",
            "server_conf": f"{job_id}/openvpn/server.conf",
            "client_ovpn": f"{job_id}/{client}.ovpn",
            "cert_password": cert_password
        })

        return jsonify({"ok": True})

    except Exception as e:
        JOB_STATUS.update({
            "state": "error",
            "progress": JOB_STATUS.get("progress", 0),
            "message": str(e)
        })
        return jsonify({"error": str(e)}), 500

@app.route("/status")
def status():
    return jsonify(JOB_STATUS)

@app.route("/download/<path:filepath>")
def download(filepath):
    return send_file(BASE_JOBS_DIR / filepath, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9192)