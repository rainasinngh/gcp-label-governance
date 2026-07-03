FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt governance_service.py governance.config.json ./

RUN pip install --no-cache-dir -r requirements.txt

ENV GOVERNANCE_CONFIG=/app/governance.config.json

CMD exec gunicorn --bind :8080 --workers 1 --threads 8 governance_service:app
