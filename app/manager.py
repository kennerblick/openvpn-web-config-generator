"""Passwortgeschützte Verwaltung der Herstellerzugänge.

Zugänge, Dateien (.ovpn, Readmes) und Passwörter liegen in SQLite unter /app/data.
Dateien und Passwörter werden mit Fernet (AES) verschlüsselt gespeichert.
"""
from flask import (Blueprint, render_template, request, redirect, url_for, session,
                   abort, flash, send_file, jsonify)
from cryptography.fernet import Fernet
from pathlib import Path
from functools import wraps
from datetime import datetime, date
import base64
import hashlib
import hmac
import io
import ipaddress
import os
import secrets
import sqlite3
import time

DATA_DIR  = Path(os.environ.get("VPNGEN_DATA", "/app/data"))
DB_PATH   = DATA_DIR / "manager.db"
ADMIN_USER = os.environ.get("VPNGEN_USER", "admin")
ADMIN_PASS = os.environ.get("VPNGEN_PASSWORD", "")
GW_IP     = os.environ.get("VPNGEN_GATEWAY_IP", "192.168.3.11")
GW_IF     = os.environ.get("VPNGEN_GATEWAY_IF", "eno1")
WAN_IF    = os.environ.get("VPNGEN_WAN_IF", "WAN1")
ENABLED   = bool(ADMIN_PASS)

bp = Blueprint("verwaltung", __name__, url_prefix="/verwaltung", template_folder="templates")

SCHEMA = """
CREATE TABLE IF NOT EXISTS zugang (
    id INTEGER PRIMARY KEY,
    hersteller TEXT NOT NULL, produkt TEXT NOT NULL,
    ansprechpartner TEXT, kontakt TEXT,
    server_host TEXT, ext_port INTEGER, proto TEXT DEFAULT 'udp',
    weg TEXT DEFAULT 'direkt', vm_ip TEXT, vm_port INTEGER,
    gueltig_bis TEXT, status TEXT DEFAULT 'aktiv', notizen TEXT,
    erstellt TEXT, geaendert TEXT
);
CREATE TABLE IF NOT EXISTS datei (
    id INTEGER PRIMARY KEY,
    zugang_id INTEGER NOT NULL REFERENCES zugang(id) ON DELETE CASCADE,
    name TEXT NOT NULL, inhalt BLOB NOT NULL, erstellt TEXT
);
CREATE TABLE IF NOT EXISTS geheimnis (
    id INTEGER PRIMARY KEY,
    zugang_id INTEGER NOT NULL REFERENCES zugang(id) ON DELETE CASCADE,
    bezeichnung TEXT NOT NULL, wert BLOB NOT NULL, erstellt TEXT
);
"""

FIELDS = ["hersteller", "produkt", "ansprechpartner", "kontakt", "server_host", "ext_port",
          "proto", "weg", "vm_ip", "vm_port", "gueltig_bis", "status", "notizen"]


# ── Schlüssel & Datenbank ─────────────────────────────────────────────────────

def _load_secret() -> bytes:
    """VPNGEN_SECRET aus der Umgebung, sonst einmalig erzeugt und im Datenverzeichnis abgelegt."""
    env = os.environ.get("VPNGEN_SECRET", "")
    if env:
        return env.encode()
    key_file = DATA_DIR / "secret.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_urlsafe(32))
        print("[verwaltung] VPNGEN_SECRET nicht gesetzt – Schlüssel in secret.key erzeugt. "
              "Für besseren Schutz VPNGEN_SECRET setzen und secret.key sichern!", flush=True)
    return key_file.read_text().strip().encode()


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET).digest()))


def encrypt(data: bytes) -> bytes:
    return FERNET.encrypt(data)


def decrypt(token: bytes) -> bytes:
    return FERNET.decrypt(token)


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


SECRET = b""
if ENABLED:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SECRET = _load_secret()
    FERNET = _fernet()
    with db() as con:
        con.executescript(SCHEMA)


_jobs: dict = {}


def init_jobs(jobs: dict, lock, jobs_dir: Path) -> None:
    """Zugriff auf die Generator-Jobs, damit Ergebnisse übernommen werden können."""
    _jobs.update(jobs=jobs, lock=lock, dir=jobs_dir)


# ── Login & CSRF ──────────────────────────────────────────────────────────────

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not ENABLED:
            return render_template("verwaltung/deaktiviert.html"), 503
        if not session.get("user"):
            return redirect(url_for("verwaltung.login", next=request.full_path))
        return view(*args, **kwargs)
    return wrapper


@bp.before_request
def check_csrf():
    if request.method == "POST" and request.endpoint != "verwaltung.login":
        sent = request.form.get("csrf") or request.headers.get("X-CSRF", "")
        token = session.get("csrf", "")
        if not token or not hmac.compare_digest(sent, token):
            abort(400, "Ungültiges Formular – bitte Seite neu laden.")


@bp.app_context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return {"csrf": session["csrf"], "verwaltung_aktiv": ENABLED}


@bp.route("/login", methods=["GET", "POST"])
def login():
    if not ENABLED:
        return render_template("verwaltung/deaktiviert.html"), 503
    error = None
    if request.method == "POST":
        user_ok = hmac.compare_digest(request.form.get("user", "").encode(), ADMIN_USER.encode())
        pass_ok = hmac.compare_digest(request.form.get("password", "").encode(), ADMIN_PASS.encode())
        if user_ok and pass_ok:
            session.clear()
            session.permanent = True
            session["user"] = ADMIN_USER
            session["csrf"] = secrets.token_urlsafe(24)
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/verwaltung") else url_for("verwaltung.liste"))
        time.sleep(1)   # bremst Passwort-Raten
        error = "Benutzer oder Passwort falsch."
    return render_template("verwaltung/login.html", error=error)


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("verwaltung.login"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_zugang(zid: int) -> sqlite3.Row:
    with db() as con:
        row = con.execute("SELECT * FROM zugang WHERE id = ?", (zid,)).fetchone()
    if not row:
        abort(404)
    return row


def form_values() -> tuple[dict, list[str]]:
    v = {f: request.form.get(f, "").strip() for f in FIELDS}
    errors = []
    if not v["hersteller"] or not v["produkt"]:
        errors.append("Hersteller und Produkt sind Pflichtfelder.")
    for f in ("ext_port", "vm_port"):
        if v[f]:
            if not v[f].isdigit() or not 1 <= int(v[f]) <= 65535:
                errors.append(f"{'Externer Port' if f == 'ext_port' else 'VM-Port'} ist ungültig.")
            else:
                v[f] = int(v[f])
        else:
            v[f] = None
    if v["vm_ip"]:
        try:
            ipaddress.ip_address(v["vm_ip"])
        except ValueError:
            errors.append("VM-IP ist ungültig.")
    if v["gueltig_bis"]:
        try:
            date.fromisoformat(v["gueltig_bis"])
        except ValueError:
            errors.append("Datum „gültig bis“ ist ungültig.")
    v["proto"]  = v["proto"] if v["proto"] in ("udp", "tcp") else "udp"
    v["weg"]    = v["weg"] if v["weg"] in ("direkt", "gateway") else "direkt"
    v["status"] = v["status"] if v["status"] in ("aktiv", "beendet") else "aktiv"
    return v, errors


def port_conflicts(port: int | None, proto: str, own_id: int | None = None) -> list[sqlite3.Row]:
    if not port:
        return []
    with db() as con:
        return con.execute(
            "SELECT id, hersteller, produkt FROM zugang "
            "WHERE ext_port = ? AND proto = ? AND status = 'aktiv' AND id IS NOT ?",
            (port, proto, own_id)).fetchall()


def nat_commands(z: sqlite3.Row) -> dict[str, str]:
    """Befehle für Mikrotik und Gateway passend zum Zugang."""
    if not (z["ext_port"] and z["vm_ip"] and z["vm_port"]):
        return {}
    comment = f'{z["hersteller"]} {z["produkt"]}'.replace('"', "'")
    if z["weg"] == "gateway":
        return {
            "Mikrotik": (f'/ip firewall nat add chain=dstnat action=dst-nat comment="{comment}" '
                         f'in-interface={WAN_IF} protocol={z["proto"]} dst-port={z["ext_port"]} '
                         f'to-addresses={GW_IP} to-ports={z["ext_port"]}'),
            f"Gateway {GW_IP}": (f'iptables -t nat -A PREROUTING -i {GW_IF} -p {z["proto"]} '
                                 f'-m {z["proto"]} --dport {z["ext_port"]} '
                                 f'-j DNAT --to-destination {z["vm_ip"]}:{z["vm_port"]}'),
        }
    return {
        "Mikrotik": (f'/ip firewall nat add chain=dstnat action=dst-nat comment="{comment}" '
                     f'in-interface={WAN_IF} protocol={z["proto"]} dst-port={z["ext_port"]} '
                     f'to-addresses={z["vm_ip"]} to-ports={z["vm_port"]}'),
    }


def import_job(zid: int, job: dict, job_dir: Path) -> None:
    """Dateien und Schlüssel-Passwörter eines Generator-Jobs übernehmen."""
    files = ["server.ovpn", "install_readme.txt", "crl.pem"]
    for c in job.get("clients", []):
        files += [f"{c['name']}.ovpn", f"{c['name']}_install_readme.txt"]
    with db() as con:
        for name in files:
            path = job_dir / name
            if path.is_file():
                con.execute("INSERT INTO datei (zugang_id, name, inhalt, erstellt) VALUES (?,?,?,?)",
                            (zid, name, encrypt(path.read_bytes()), now()))
        for c in job.get("clients", []):
            if c.get("password"):
                con.execute("INSERT INTO geheimnis (zugang_id, bezeichnung, wert, erstellt) VALUES (?,?,?,?)",
                            (zid, f"Schlüssel-Passwort {c['name']}", encrypt(c["password"].encode()), now()))


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/")
@login_required
def liste():
    q      = request.args.get("q", "").strip()
    status = request.args.get("status", "aktiv")
    sql    = "SELECT * FROM zugang WHERE 1=1"
    args: list = []
    if status in ("aktiv", "beendet"):
        sql += " AND status = ?"
        args.append(status)
    if q:
        sql += (" AND (hersteller LIKE ? OR produkt LIKE ? OR ansprechpartner LIKE ? "
                "OR vm_ip LIKE ? OR CAST(ext_port AS TEXT) LIKE ? OR notizen LIKE ?)")
        args += [f"%{q}%"] * 6
    sql += " ORDER BY status, hersteller COLLATE NOCASE, produkt COLLATE NOCASE"
    with db() as con:
        rows = con.execute(sql, args).fetchall()
    return render_template("verwaltung/liste.html", rows=rows, q=q, status=status,
                           heute=date.today().isoformat())


@bp.route("/neu", methods=["GET", "POST"])
@login_required
def neu():
    job_id = request.values.get("job", "")
    with _jobs["lock"]:
        job = dict(_jobs["jobs"].get(job_id, {}))
    job = job if job.get("state") == "done" else {}

    if request.method == "POST":
        v, errors = form_values()
        if not errors:
            with db() as con:
                cur = con.execute(
                    f"INSERT INTO zugang ({', '.join(FIELDS)}, erstellt, geaendert) "
                    f"VALUES ({', '.join('?' * (len(FIELDS) + 2))})",
                    [v[f] for f in FIELDS] + [now(), now()])
                zid = cur.lastrowid
            if job:
                import_job(zid, job, _jobs["dir"] / job_id)
            for c in port_conflicts(v["ext_port"], v["proto"], zid):
                flash(f"Achtung: Port {v['ext_port']}/{v['proto']} ist auch bei "
                      f"„{c['hersteller']} – {c['produkt']}“ aktiv vergeben.", "warn")
            flash("Zugang gespeichert.", "ok")
            return redirect(url_for("verwaltung.detail", zid=zid))
        for e in errors:
            flash(e, "error")
        z = v
    else:
        p = job.get("params", {})
        z = {f: "" for f in FIELDS} | {
            "server_host": p.get("server_ip", ""), "ext_port": p.get("port", ""),
            "proto": p.get("proto", "udp"), "vm_port": p.get("port", ""),
            "weg": "direkt", "status": "aktiv",
        }
    return render_template("verwaltung/form.html", z=z, job=job, job_id=job_id, titel="Neuer Zugang")


@bp.route("/<int:zid>")
@login_required
def detail(zid: int):
    z = get_zugang(zid)
    with db() as con:
        dateien  = con.execute("SELECT id, name, erstellt FROM datei WHERE zugang_id = ? ORDER BY name",
                               (zid,)).fetchall()
        geheimes = con.execute("SELECT id, bezeichnung, erstellt FROM geheimnis WHERE zugang_id = ? "
                               "ORDER BY bezeichnung", (zid,)).fetchall()
    return render_template("verwaltung/detail.html", z=z, dateien=dateien, geheimes=geheimes,
                           befehle=nat_commands(z), konflikte=port_conflicts(z["ext_port"], z["proto"], zid),
                           heute=date.today().isoformat())


@bp.route("/<int:zid>/bearbeiten", methods=["GET", "POST"])
@login_required
def bearbeiten(zid: int):
    z = get_zugang(zid)
    if request.method == "POST":
        v, errors = form_values()
        if not errors:
            with db() as con:
                con.execute(f"UPDATE zugang SET {', '.join(f + ' = ?' for f in FIELDS)}, geaendert = ? "
                            f"WHERE id = ?", [v[f] for f in FIELDS] + [now(), zid])
            flash("Änderungen gespeichert.", "ok")
            return redirect(url_for("verwaltung.detail", zid=zid))
        for e in errors:
            flash(e, "error")
        z = v | {"id": zid}
    return render_template("verwaltung/form.html", z=z, job={}, job_id="", titel="Zugang bearbeiten")


@bp.route("/<int:zid>/loeschen", methods=["POST"])
@login_required
def loeschen(zid: int):
    get_zugang(zid)
    with db() as con:
        con.execute("DELETE FROM zugang WHERE id = ?", (zid,))
    flash("Zugang gelöscht.", "ok")
    return redirect(url_for("verwaltung.liste"))


@bp.route("/<int:zid>/datei", methods=["POST"])
@login_required
def datei_hochladen(zid: int):
    get_zugang(zid)
    f = request.files.get("datei")
    if not f or not f.filename:
        flash("Keine Datei ausgewählt.", "error")
    else:
        name = Path(f.filename).name[:120]
        with db() as con:
            con.execute("INSERT INTO datei (zugang_id, name, inhalt, erstellt) VALUES (?,?,?,?)",
                        (zid, name, encrypt(f.read()), now()))
        flash(f"„{name}“ hochgeladen.", "ok")
    return redirect(url_for("verwaltung.detail", zid=zid))


@bp.route("/<int:zid>/datei/<int:did>")
@login_required
def datei_download(zid: int, did: int):
    with db() as con:
        d = con.execute("SELECT name, inhalt FROM datei WHERE id = ? AND zugang_id = ?", (did, zid)).fetchone()
    if not d:
        abort(404)
    return send_file(io.BytesIO(decrypt(d["inhalt"])), as_attachment=True, download_name=d["name"])


@bp.route("/<int:zid>/datei/<int:did>/loeschen", methods=["POST"])
@login_required
def datei_loeschen(zid: int, did: int):
    with db() as con:
        con.execute("DELETE FROM datei WHERE id = ? AND zugang_id = ?", (did, zid))
    flash("Datei gelöscht.", "ok")
    return redirect(url_for("verwaltung.detail", zid=zid))


@bp.route("/<int:zid>/geheimnis", methods=["POST"])
@login_required
def geheimnis_neu(zid: int):
    get_zugang(zid)
    bez  = request.form.get("bezeichnung", "").strip()[:120]
    wert = request.form.get("wert", "")
    if not bez or not wert:
        flash("Bezeichnung und Passwort angeben.", "error")
    else:
        with db() as con:
            con.execute("INSERT INTO geheimnis (zugang_id, bezeichnung, wert, erstellt) VALUES (?,?,?,?)",
                        (zid, bez, encrypt(wert.encode()), now()))
        flash("Passwort gespeichert.", "ok")
    return redirect(url_for("verwaltung.detail", zid=zid))


@bp.route("/<int:zid>/geheimnis/<int:gid>", methods=["POST"])
@login_required
def geheimnis_zeigen(zid: int, gid: int):
    """Passwort nur auf Klick und per POST (mit CSRF) herausgeben – steht nie im HTML."""
    with db() as con:
        g = con.execute("SELECT wert FROM geheimnis WHERE id = ? AND zugang_id = ?", (gid, zid)).fetchone()
    if not g:
        abort(404)
    return jsonify({"wert": decrypt(g["wert"]).decode()})


@bp.route("/<int:zid>/geheimnis/<int:gid>/loeschen", methods=["POST"])
@login_required
def geheimnis_loeschen(zid: int, gid: int):
    with db() as con:
        con.execute("DELETE FROM geheimnis WHERE id = ? AND zugang_id = ?", (gid, zid))
    flash("Passwort gelöscht.", "ok")
    return redirect(url_for("verwaltung.detail", zid=zid))
