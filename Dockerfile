FROM python:3.11-slim

WORKDIR /app
COPY edgeguard.py config.json ./

EXPOSE 8080

CMD ["python", "-u", "edgeguard.py"]
