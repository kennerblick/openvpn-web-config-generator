FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y openvpn easy-rsa && \
    rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 9192

CMD ["python", "app.py"]