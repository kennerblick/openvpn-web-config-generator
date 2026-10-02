FROM alpine:3.20

RUN apk add --no-cache \
    openvpn \
    easy-rsa \
    python3 \
    py3-pip \
    openssl \
    bash \
    py3-cryptography

WORKDIR /app
COPY app/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

COPY app/ .

# Ohne root-Rechte laufen – für die Generierung werden keine Privilegien benötigt
RUN adduser -D -H -u 10001 vpngen \
 && mkdir -p /app/jobs /app/data \
 && chown vpngen:vpngen /app/jobs /app/data \
 && chmod 700 /app/jobs /app/data
USER vpngen

EXPOSE 9192
CMD ["python3", "app.py"]
