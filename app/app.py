from flask import Flask, request, render_template, jsonify, send_file
import subprocess
import secrets
import string
import os
import re

app = Flask(__name__)
OPENVPN_DIR = "/etc/openvpn"

def valid_ip(ip):
    return re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip)

def gen_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/create", methods=["POST"])
def create():
    server_ip = request.form.get("server_ip")
    port = request.form.get("port")
    client = request.form.get("client")

    if not valid_ip(server_ip):
        return jsonify({"error": "Ungültige IP-Adresse"}), 400

    if not port.isdigit() or not (1 <= int(port) <= 65535):
        return jsonify({"error": "Ungültiger Port"}), 400

    username = client
    password = gen_password()

    os.makedirs(OPENVPN_DIR, exist_ok=True)

    # Server config
    subprocess.run([
        "ovpn_genconfig",
        "-u", f"udp://{server_ip}:{port}",
        "-C", "AES-256-GCM",
        "-a", "SHA512",
        "-c"
    ], cwd=OPENVPN_DIR, check=True)

    # PKI
    if not os.path.exists(f"{OPENVPN_DIR}/pki"):
        subprocess.run(["ovpn_initpki", "nopass"], cwd=OPENVPN_DIR, check=True)

    # Benutzer anlegen
    subprocess.run(
        f"echo {password} | ovpn_adduser {username}",
        shell=True,
        cwd=OPENVPN_DIR,
        check=True
    )

    # Client Datei erzeugen
    client_file = f"/app/{username}.ovpn"
    subprocess.run(
        f"ovpn_getclient {username} > {client_file}",
        shell=True,
        check=True
    )

    return jsonify({
        "username": username,
        "password": password,
        "client_file": f"{username}.ovpn"
    })

@app.route("/download/<name>")
def download(name):
    return send_file(f"/app/{name}", as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9192)