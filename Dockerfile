FROM alpine:3.20

RUN apk add --no-cache \
    openvpn \
    easy-rsa \
    python3 \
    py3-pip \
    openssl \
    bash

WORKDIR /app
COPY app/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

COPY app/ .
RUN mkdir -p /app/jobs

EXPOSE 9192
CMD ["python3", "app.py"]
