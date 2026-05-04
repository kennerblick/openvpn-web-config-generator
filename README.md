# OpenVPN Web Config Generator

Webbasierter Generator für wegwerf-OpenVPN-Server- und Client-Konfigurationen.  
Einfach Server-IP eingeben, auf „VPN erstellen" klicken – fertig.

## Features

- **1-Klick-Generierung** – nur IP-Adresse oder Hostname erforderlich
- **Automatische PKI** – CA, Server- & Client-Zertifikate via Easy-RSA (EC/secp384r1)
- **Starke Verschlüsselung** – AES-256-GCM, SHA-512, TLS-Crypt HMAC-Firewall
- **Client `.ovpn`** – alle Zertifikate inline eingebettet, sofort importierbar
- **Benutzername + Passwort** – automatisch generiert, für `auth-user-pass`-Auth
- **Konfigurierbar** – Protokoll (UDP/TCP), Port, Zertifikat-Gültigkeit (30–3650 Tage)
- **Zwei Downloads** – Server-Bundle (ZIP) & Client-Paket (ZIP + .ovpn einzeln)
- **Automatische Bereinigung** – Jobs werden nach 24 Stunden gelöscht

## Schnellstart

```bash
docker-compose up -d
```

Öffne dann [http://localhost:9192](http://localhost:9192).

## Server-Bundle inhalt

| Datei | Inhalt |
|-------|--------|
| `server.conf` | OpenVPN-Serverkonfiguration mit eingebetteten Zertifikaten |
| `userpass.txt` | `benutzername:passwort` – für `auth-user-pass-verify` |
| `checkpwd.sh` | Authentifizierungsskript (via-env) |
| `README.txt` | Schritt-für-Schritt-Anleitung |

## Client-Paket Inhalt

| Datei | Inhalt |
|-------|--------|
| `<client>.ovpn` | Vollständige Client-Konfiguration (Zertifikate inline) |
| `credentials.txt` | VPN-Benutzername & Passwort zum Aufbewahren |

## Technische Details

- **Base Image**: `alpine:3.20`
- **PKI**: Easy-RSA 3.x, EC-Schlüssel (secp384r1), SHA-512
- **Kein DH** – ECDH für Forward Secrecy, `dh none`
- **TLS-Crypt** – HMAC-basierte TLS-Firewall (schützt vor Port-Scanning)
- **Sicherheit**: Eingabe-Validierung, keine Shell-Injection, Pfad-Traversal-Schutz
- **Nebenläufigkeit**: Thread-basiert, mehrere Jobs gleichzeitig möglich
