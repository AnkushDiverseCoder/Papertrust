# Papertrust: self-hosted document signing.
# Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant). Licensed under the Apache License 2.0.
FROM node:24-alpine

WORKDIR /app

# Chromium renders the PDFs. The Noto fonts cover Latin, Devanagari and the rupee sign; add others you need.
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont font-noto font-noto-devanagari \
 && mkdir -p /data && chown node:node /data

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY bin ./bin
COPY src ./src
COPY LICENSE NOTICE README.md ./

ENV NODE_ENV=production \
    PORT=4100 \
    PAPERTRUST_DATA_DIR=/data

# runs as the unprivileged "node" user; the keystore lives on the /data volume
USER node
VOLUME /data
EXPOSE 4100

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4100)+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"

CMD ["node", "bin/papertrust.mjs", "start"]
