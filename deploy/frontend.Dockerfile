# The dashboard (E4, M15).
#
# Copyright (c) 2026 Ekrami-Labs. All rights reserved.
#
# Built once, served as static files. Nginx proxies /api to the UI API so the
# browser talks to one origin — which keeps the CORS allow-list (A1) short
# rather than pushing another origin into it.
FROM node:22-alpine AS build

WORKDIR /build

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine

COPY --from=build /build/dist /usr/share/nginx/html
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
