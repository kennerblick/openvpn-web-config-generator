from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import subprocess
import os
import uuid
import secrets
import string

app = Flask(__name__)

# Basisverzeichnis für Job-PKIs
BASE_JOBS_DIR = Path("/app/jobs")
BASE_JOBS_DIR.mkdir(parents=True, exist_ok=True)

# Globaler Job-Status (ein Job zur Zeit)
JOB_STATUS = {
    "state": "idle",      # idle | running | done | error
    "progress": 0,        # 0–100
    "message": "",
    "server_conf": None,
    "client_ovpn": None,
    "username": None,
    "password": None,
}

def update(progress, message):
    JOB_STATUS["state"] = "running"
    JOB_STATUS["progress"] = progress
    JOB_STATUS["message"] = message

def gen_password(length=16):
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/create", methods=["POST"])
def create():
    try:
        # -------- Eingaben mit Defaults --------
        server_ip = request.form["server_ip"]
        port = request.form.get("port", "1194")
        proto = request.form.get("proto", "udp")
        client = request.form.get("client", "clientname")

        # -------- Job-Struktur --------
        job_id = f"job-{uuid.uuid4().hex[:6]}"
        job_dir = BASE_JOBS_DIR / job_id
        ovpn_dir = job_dir / "openvpn"
        ovpn_dir.mkdir(parents=True)

        password = gen_password()

        # -------- Umgebung für kylemanna/openvpn --------
        env = os.environ.copy()
        env["OPENVPN"] = str(ovpn_dir)
        env["EASYRSA_BATCH"] = "1"
        env["EASYRSA_REQ_CN"] = "job-ca"

        # -------- Schritt 1: Server-Konfiguration --------
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

        # -------- Schritt 2: PKI initialisieren (Job-PKI) --------
        update(50, "Initialisiere einmalige PKI")

        subprocess.run(
            ["ovpn_initpki", "nopass"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )

        # -------- Schritt 3: Client-Zertifikat + Config --------
        update(80, "Erzeuge Client-Konfiguration")

        subprocess.run(
            f"echo {password} | ovpn_adduser {client}",
            shell=True,
            env=env,
            check=True
        )

        client_ovpn = job_dir / f"{client}.ovpn"
        subprocess.run(
            f"ovpn_getclient {client} > {client_ovpn}",
            shell=True,
            env=env,
            check=True
        )

        server_conf = ovpn_dir / "server.conf"

        # -------- Fertig --------
        JOB_STATUS.update({
            "state": "done",
            "progress": 100,
            "message": "VPN-Konfiguration fertig",
            "server_conf": f"{job_id}/openvpn/server.conf",
            "client_ovpn": f"{job_id}/{client}.ovpn",
            "username": client,
            "password": password,
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