FROM kylemanna/openvpn

RUN apk add --no-cache python3 py3-pip

WORKDIR /app

COPY app/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 9192

CMD ["python3", "app.py"]