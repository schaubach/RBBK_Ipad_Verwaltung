# Frontend Dockerfile für React (OHNE yarn.lock)
FROM node:20-alpine as build

# Arbeitsverzeichnis setzen
WORKDIR /app

# Yarn Konfiguration für bessere Netzwerk-Stabilität
RUN yarn config set network-timeout 300000 && \
    yarn config set registry https://registry.npmjs.org/

# Kopiere nur package.json für Docker Layer Caching
COPY package.json ./

# Abhängigkeiten installieren
# --prefer-offline: Nutzt lokalen Yarn-Cache (schneller!)
# Funktioniert auch OHNE yarn.lock
RUN yarn install --network-timeout 300000 --prefer-offline || \
    yarn install --network-timeout 300000

# Build-Argument für Backend-URL
ARG REACT_APP_BACKEND_URL
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL

# Anwendung kopieren (erst jetzt, für besseres Caching)
COPY . .

# Anwendung bauen
RUN yarn build

# Build-Artefakte in Volume kopieren
FROM alpine:latest
WORKDIR /app
COPY --from=build /app/build ./build

# Dummy-Kommando (Container wird nur für Build-Artefakte verwendet)
CMD ["echo", "Frontend build completed"]