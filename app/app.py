from flask import Flask, render_template, request, jsonify, send_file
import subprocess, os, secrets, string, uuid
from pathlib import Path

app = Flask(__name__)
BASE_JOBS_DIR = Path("/app/jobs")
BASE_JOBS_DIR.mkdir(exist_ok=True)

JOB_STATUS = {"state":"idle","progress":0,"message":""}

def update(p,m): JOB_STATUS.update({"state":"running","progress":p,"message":m})

def gen_pw(n=16): return ''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(n))

@app.route("/")
def index(): return render_template("index.html")

@app.route("/create", methods=["POST"])
def create():
    try:
        job = f"job-{uuid.uuid4().hex[:6]}"
        jobdir = BASE_JOBS_DIR/job
        ovpn = jobdir/"openvpn"
        ovpn.mkdir(parents=True)
        ip=request.form["server_ip"]
        port=request.form.get("port","1194")
        proto=request.form.get("proto","udp")
        client=request.form.get("client","clientname")
        pw=gen_pw()
        env=os.environ.copy(); env["OPENVPN"]=str(ovpn)
        update(20,"Server-Konfiguration")
        subprocess.run(["ovpn_genconfig","-u",f"{proto}://{ip}:{port}","-C","AES-256-GCM","-a","SHA512","-c"],env=env,check=True)
        update(50,"PKI initialisieren")
        subprocess.run("echo yes | ovpn_initpki nopass",shell=True,env=env,check=True)
        update(80,"Client erzeugen")
        subprocess.run(f"echo {pw} | ovpn_adduser {client}",shell=True,env=env,check=True)
        subprocess.run(f"ovpn_getclient {client} > {jobdir}/{client}.ovpn",shell=True,env=env,check=True)
        JOB_STATUS.update({"state":"done","progress":100,"message":"Fertig",
            "server":f"{job}/openvpn/server.conf",
            "client":f"{job}/{client}.ovpn",
            "user":client,"password":pw})
        return jsonify(ok=True)
    except Exception as e:
        JOB_STATUS.update({"state":"error","message":str(e)})
        return jsonify(error=str(e)),500

@app.route("/status")
def status(): return jsonify(JOB_STATUS)

@app.route("/download/<path:p>")
def dl(p): return send_file(BASE_JOBS_DIR/p, as_attachment=True)

if __name__=="__main__": app.run("0.0.0.0",9192)
