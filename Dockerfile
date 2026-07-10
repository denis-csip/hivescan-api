FROM python:3.11-slim

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code de l'API
COPY app/ ./

# Données de financement (santé/levées) enrichies hors ligne — embarquées dans l'image.
COPY funding_ch.json funding_fr.json funding_no.json funding_dk.json ./
ENV FUNDING_DIR=/app

EXPOSE 8000

# Render fournit $PORT ; défaut 8000 en local.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
