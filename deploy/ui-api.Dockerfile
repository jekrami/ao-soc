# The dashboard's API (E4, M15).
#
# Copyright (c) 2026 Ekrami-Labs. All rights reserved.
#
# Holds no decisions of its own: it reads the broker and shapes what the UI
# needs. Nothing here is a source of record, so it carries no volume — which is
# also why it is the safe service to restart during a shift.
FROM node:22-alpine

ENV NODE_ENV=production

WORKDIR /srv

COPY backend/package.json backend/package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY backend/ ./

USER node

ENV PORT=4000
EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:4000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
