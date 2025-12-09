# Backend Dockerfile für FastAPI (optimiert mit Multi-Stage Build)
# Build-Stage: Hier werden Python-Pakete kompiliert
FROM python:3.11-slim-bullseye as builder

WORKDIR /app

# Nur Build-Abhängigkeiten installieren
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Python-Abhängigkeiten kopieren und installieren
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Runtime-Stage: Kleineres finales Image ohne Build-Tools
FROM python:3.11-slim-bullseye

WORKDIR /app

# Nur Runtime-Abhängigkeiten installieren (ohne gcc!)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Python-Pakete von Builder-Stage kopieren
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Anwendung kopieren
COPY . .

# Upload-Verzeichnis erstellen
RUN mkdir -p uploads

# Port freigeben
EXPOSE 8001

# Healthcheck
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8001/api/auth/setup || exit 1

# Startkommando
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", "--reload"]