# OpenVPN Web Config Generator

Webbasierter Generator für wegwerf-OpenVPN-Server- und Client-Konfigurationen.  
Einfach Server-IP eingeben, auf „VPN erstellen" klicken – fertig.

## Features

**Generator** (offen, ohne Anmeldung)

- **1-Klick-Generierung** – nur IP-Adresse oder Hostname erforderlich
- **Automatische PKI** – CA, Server- & Client-Zertifikate via Easy-RSA (EC/secp384r1)
- **Starke Verschlüsselung** – AES-256-GCM, SHA-512, TLS-Crypt HMAC-Firewall
- **Client `.ovpn`** – alle Zertifikate inline eingebettet, sofort importierbar
- **Passwortgeschützte Client-Schlüssel** – optional, Passwort wird automatisch generiert
- **Konfigurierbar** – Protokoll (UDP/TCP), Port, Zertifikat-Gültigkeit (30–3650 Tage)
- **Automatische Bereinigung** – Jobs werden nach 24 Stunden gelöscht

**Verwaltung** (`/verwaltung`, passwortgeschützt)

- **Herstellerzugänge dokumentieren** – Hersteller, Produkt, Ansprechpartner, Port, Ziel-VM,
  Weg (direkt oder über Gateway), Gültigkeit, Status, Notizen
- **Übernahme aus dem Generator** – Button „In Verwaltung speichern“ übernimmt Configs,
  Readmes und Schlüssel-Passwörter
- **Verschlüsselte Ablage** – Dateien und Passwörter liegen verschlüsselt (Fernet/AES) in SQLite;
  Passwörter werden nur auf Klick angezeigt
- **Weitere Dateien und Passwörter** – z. B. VM-Login, Dokumente des Herstellers
- **Portkonflikt-Warnung** und fertige Befehle für Mikrotik bzw. Gateway (iptables)
- **Suche und Filter**, abgelaufene Zugänge werden markiert

## Schnellstart

```bash
cat > .env <<EOT
VPNGEN_PASSWORD=$(openssl rand -base64 24)
VPNGEN_SECRET=$(openssl rand -base64 32)
EOT
chmod 600 .env
docker compose up -d --build
```

Generator: `http://<server>:9192` – Verwaltung: `http://<server>:9192/verwaltung` (Benutzer `admin`).

| Variable | Standard | Bedeutung |
|----------|----------|-----------|
| `VPNGEN_USER` | `admin` | Benutzername für die Verwaltung |
| `VPNGEN_PASSWORD` | leer | Passwort für die Verwaltung – leer = Verwaltung deaktiviert |
| `VPNGEN_SECRET` | leer | Schlüssel für die verschlüsselte Ablage (siehe unten) |
| `VPNGEN_COOKIE_SECURE` | `0` | `1`, wenn nur per HTTPS erreichbar (Reverse-Proxy) |
| `VPNGEN_GATEWAY_IP` | `192.168.100.1` | Gateway für die vorgeschlagenen NAT-Befehle |
| `VPNGEN_GATEWAY_IF` | `eno1` | Eingangs-Interface am Gateway |
| `VPNGEN_WAN_IF` | `WAN1` | WAN-Interface am Mikrotik |
| `VPNGEN_BIND` | `0.0.0.0` | Bind-Adresse innerhalb des Containers |

### Schlüssel und Backup

Ohne `VPNGEN_SECRET` erzeugt die Verwaltung beim ersten Start selbst einen Schlüssel und legt ihn
als `secret.key` im Datenvolume ab. Besser ist ein eigener Wert in der `.env`, dann liegt der
Schlüssel nicht neben den Daten. **Geht der Schlüssel verloren oder wird er geändert, sind die
gespeicherten Dateien und Passwörter nicht mehr lesbar** – also z. B. in Passbolt sichern.

Gesichert werden muss das Volume `vpn-data` (Datenbank `manager.db`) zusammen mit dem Schlüssel:

```bash
docker run --rm -v openvpn-web-config-generator_vpn-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/vpn-data-$(date +%F).tgz -C /data .
```

Die Verwaltung läuft über HTTP mit Login per Formular. Im Netz sollte sie hinter einem
Reverse-Proxy mit HTTPS stehen (dann `VPNGEN_COOKIE_SECURE=1`).

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
- **Sicherheit**: Login mit CSRF-Schutz für die Verwaltung, Eingabe-Validierung, keine Shell-Injection, Download-Whitelist
  (PKI-Dateien wie `ca.key` sind nie abrufbar), 128-Bit-Job-IDs, restriktive Dateirechte,
  Container ohne root und ohne Capabilities
- **Zielnetz-Isolation**: Ist ein Zielnetz angegeben, enthält die Server-Anleitung
  Firewall-Regeln, die VPN-Clients ausschließlich dorthin lassen
- **Nebenläufigkeit**: Thread-basiert, mehrere Jobs gleichzeitig möglich
