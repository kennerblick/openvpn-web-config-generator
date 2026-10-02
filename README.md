# OpenVPN Web Config Generator

Webbasierter Generator für wegwerf-OpenVPN-Server- und Client-Konfigurationen.  
Einfach Server-IP eingeben, auf „VPN erstellen" klicken – fertig.

## Features

- **1-Klick-Generierung** – nur IP-Adresse oder Hostname erforderlich
- **Automatische PKI** – CA, Server- & Client-Zertifikate via Easy-RSA (EC/secp384r1)
- **Starke Verschlüsselung** – AES-256-GCM, SHA-512, TLS-Crypt HMAC-Firewall
- **Client `.ovpn`** – alle Zertifikate inline eingebettet, sofort importierbar
- **Passwortgeschützte Client-Schlüssel** – optional, Passwort wird automatisch generiert
- **Login-Schutz** – Weboberfläche per HTTP Basic Auth gesichert
- **Konfigurierbar** – Protokoll (UDP/TCP), Port, Zertifikat-Gültigkeit (30–3650 Tage)
- **Zwei Downloads** – Server-Bundle (ZIP) & Client-Paket (ZIP + .ovpn einzeln)
- **Automatische Bereinigung** – Jobs werden nach 24 Stunden gelöscht

## Schnellstart

```bash
VPNGEN_PASSWORD='ein-langes-passwort' docker-compose up -d
```

Öffne dann [http://localhost:9192](http://localhost:9192) und melde dich als `admin` an.
Ist `VPNGEN_PASSWORD` nicht gesetzt, wird beim Start ein Zufallspasswort erzeugt:

```bash
docker logs openvpn-web
```

| Variable | Standard | Bedeutung |
|----------|----------|-----------|
| `VPNGEN_USER` | `admin` | Benutzername für die Weboberfläche |
| `VPNGEN_PASSWORD` | zufällig | Passwort für die Weboberfläche |
| `VPNGEN_BIND` | `0.0.0.0` | Bind-Adresse innerhalb des Containers |

Standardmäßig ist der Port nur auf `127.0.0.1` veröffentlicht. Soll der Generator im Netz
erreichbar sein (z. B. für den QR-Code-Download am Handy), den Port in `docker-compose.yml`
freigeben und idealerweise einen Reverse-Proxy mit HTTPS davorschalten – Basic Auth
überträgt das Passwort sonst im Klartext.

> **Update von einer älteren Version:** Der Container läuft jetzt ohne root-Rechte.
> Ein bestehendes Volume gehört noch root – einmalig `docker-compose down -v` ausführen
> (löscht die alten, ohnehin temporären Jobs).

## Server-Bundle inhalt

| Datei | Inhalt |
|-------|--------|
| `server.ovpn` | OpenVPN-Serverkonfiguration mit eingebetteten Zertifikaten |
| `install_readme.txt` | Schritt-für-Schritt-Anleitung inkl. Firewall-Regeln |
| `crl.pem` | Sperrliste (nur wenn CRL aktiviert) |

## Client-Paket Inhalt

| Datei | Inhalt |
|-------|--------|
| `<client>.ovpn` | Vollständige Client-Konfiguration (Zertifikate inline) |
| `<client>_install_readme.txt` | Installationsanleitung für das gewählte Betriebssystem |
| `zugangsdaten.txt` | Schlüssel-Passwörter (nur bei verschlüsselten Client-Keys) |

## Technische Details

- **Base Image**: `alpine:3.20`
- **PKI**: Easy-RSA 3.x, EC-Schlüssel (secp384r1), SHA-512
- **Kein DH** – ECDH für Forward Secrecy, `dh none`
- **TLS-Crypt** – HMAC-basierte TLS-Firewall (schützt vor Port-Scanning)
- **Sicherheit**: Basic Auth, Eingabe-Validierung, keine Shell-Injection, Download-Whitelist
  (PKI-Dateien wie `ca.key` sind nie abrufbar), 128-Bit-Job-IDs, restriktive Dateirechte,
  Container ohne root und ohne Capabilities
- **Zielnetz-Isolation**: Ist ein Zielnetz angegeben, enthält die Server-Anleitung
  Firewall-Regeln, die VPN-Clients ausschließlich dorthin lassen
- **Nebenläufigkeit**: Thread-basiert, mehrere Jobs gleichzeitig möglich
