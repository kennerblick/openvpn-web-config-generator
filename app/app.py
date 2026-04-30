from flask import Flask, render_template, request, jsonify, send_file
import subprocess, os, secrets, string, re

app = Flask(__name__)

OPENVPN_DIR = "/etc/openvpn"
JOB_STATUS = {
    "state": "idle",
    "progress": 0,
    "message": "",
    "server_conf": None,
    "client_ovpn": None
}

def update(p, msg):
    JOB_STATUS.update({"state": "running", "progress": p, "message": msg})

def gen_password(n=16):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(n))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/create", methods=["POST"])
def create():
    try:
        server_ip = request.form["server_ip"]
        port = request.form.get("port","1194")
        proto = request.form.get("proto","udp")
        client = request.form.get("client","clientname")
        expire = request.form.get("expire","365")

        update(10, "Initialisiere Umgebung")

        subprocess.run([
            "ovpn_genconfig",
            "-u", f"{proto}://{server_ip}:{port}",
            "-C","AES-256-GCM",
            "-a","SHA512",
            "-c"
        ], cwd=OPENVPN_DIR, check=True)

        update(40, "Initialisiere PKI")
        if not os.path.exists(f"{OPENVPN_DIR}/pki"):
            subprocess.run(["ovpn_initpki","nopass"], cwd=OPENVPN_DIR, check=True)

        update(70, "Erzeuge Client-Zertifikat")
        pwd = gen_password()
        subprocess.run(f"echo {pwd} | ovpn_adduser {client}", shell=True, cwd=OPENVPN_DIR, check=True)

        client_file = f"/app/{client}.ovpn"
        subprocess.run(f"ovpn_getclient {client} > {client_file}", shell=True, check=True)

        update(100, "Fertig")

        JOB_STATUS.update({
            "state": "done",
            "server_conf": "server.conf",
            "client_ovpn": f"{client}.ovpn",
            "username": client,
            "password": pwd
        })

        return jsonify({"ok": True})

    except Exception as e:
        JOB_STATUS.update({"state":"error","message":str(e)})
        return jsonify({"error":str(e)}), 500

@app.route("/status")
def status():
    return jsonify(JOB_STATUS)

@app.route("/download/<name>")
def download(name):
    return send_file(f"/app/{name}", as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9192)