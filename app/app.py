from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import subprocess
import os
import uuid
import secrets
import string

app = Flask(__name__)

BASE_JOBS_DIR = Path("/app/jobs")
BASE_JOBS_DIR.mkdir(parents=True, exist_ok=True)

JOB_STATUS = {
    "state": "idle",
    "progress": 0,
    "message": "",
    "server_conf": None,
    "client_ovpn": None,
    "cert_password": None
}

# ---------- Utilities ----------

def update(progress, message):
    JOB_STATUS["state"] = "running"
    JOB_STATUS["progress"] = progress
    JOB_STATUS["message"] = message

def generate_cert_password(length=12):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+"

    # Pflichtzeichen
    password = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special)
    ]

    all_chars = upper + lower + digits + special
    password += [secrets.choice(all_chars) for _ in range(length - 4)]

    secrets.SystemRandom().shuffle(password)
    return "".join(password)

# ---------- Routes ----------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/create", methods=["POST"])
def create():
    try:
        server_ip = request.form["server_ip"]
        port = request.form.get("port", "1194")
        proto = request.form.get("proto", "udp")
        client = request.form.get("client", "clientname")

        job_id = f"job-{uuid.uuid4().hex[:6]}"
        job_dir = BASE_JOBS_DIR / job_id
        ovpn_dir = job_dir / "openvpn"
        ovpn_dir.mkdir(parents=True)

        cert_password = generate_cert_password()

        env = os.environ.copy()
        env["OPENVPN"] = str(ovpn_dir)
        env["EASYRSA_BATCH"] = "1"
        env["EASYRSA_REQ_CN"] = "job-ca"

        # ---- Step 1: Server config ----
        update(15, "Erzeuge Server-Konfiguration")

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

        # ---- Step 2: PKI ----
        update(40, "Initialisiere Job-PKI")

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

        subprocess.run(
            [
                "easyrsa",
                "build-client-full",
                client,
                "pass"
            ],
            env=dict(env, EASYRSA_PASSPHRASE=cert_password),
            cwd=ovpn_dir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )

        # ---- Step 4: Client config ----
        client_ovpn = job_dir / f"{client}.ovpn"
        subprocess.run(
            f"ovpn_getclient {client} > {client_ovpn}",
            shell=True,
            env=env,
            check=True
        )

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