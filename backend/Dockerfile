# Backend için optimize edilmiş çok aşamalı Dockerfile
FROM node:18-bullseye-slim AS base

# Çalışma dizinini ayarla
WORKDIR /app

# Kullanıcı oluştur (güvenlik için)
RUN groupadd -g 1001 nodejs && \
    useradd -s /bin/bash -u 1001 -g nodejs nodejs

# Bağımlılıklar aşaması - Production
FROM base AS deps-prod
COPY package*.json ./
COPY prisma ./prisma/

# Configure Prisma for corporate environments
ENV PRISMA_CLI_BINARY_TARGETS="debian-openssl-1.1.x"
ENV NODE_TLS_REJECT_UNAUTHORIZED=0

RUN npm config set strict-ssl false && \
    npm ci --only=production --no-audit --no-fund && \
    npm cache clean --force && \
    npx prisma generate

# Bağımlılıklar aşaması - Development
FROM base AS deps-dev
COPY package*.json ./
COPY prisma ./prisma/

# Configure Prisma for corporate environments
ENV PRISMA_CLI_BINARY_TARGETS="debian-openssl-1.1.x"
ENV NODE_TLS_REJECT_UNAUTHORIZED=0

RUN npm config set strict-ssl false && \
    npm ci --no-audit --no-fund && \
    npm cache clean --force && \
    npx prisma generate

# Build aşaması
FROM deps-dev AS builder
ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

# Kaynak kodunu kopyala
COPY --chown=nodejs:nodejs . .

# TypeScript kodunu derle
RUN npm run build

# Üretim aşaması
FROM base AS production

# Ortam değişkenlerini ayarla
ENV NODE_ENV=production
ENV PORT=3002
ENV NODE_OPTIONS="--max-old-space-size=768"

# Gerekli dizinleri oluştur
RUN mkdir -p /app/uploads/mobile /app/data /app/logs && \
    chown -R nodejs:nodejs /app

# Üretim bağımlılıklarını ve Prisma'yı kopyala
COPY --from=deps-prod --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=deps-prod --chown=nodejs:nodejs /app/prisma ./prisma

# Derlenmiş kodu ve diğer gerekli dosyaları kopyala
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./
COPY --from=builder --chown=nodejs:nodejs /app/data ./data

# Kullanıcıyı değiştir
USER nodejs

# Port'u expose et
EXPOSE 3002

# Health check ekle (curl node:18-alpine'da mevcut)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3002/health || exit 1

# Graceful shutdown için signal handling
STOPSIGNAL SIGTERM

# Uygulamayı başlat (dumb-init olmadan - node zaten signal handling yapıyor)
CMD ["node", "dist/src/index.js"]

# Geliştirme aşaması
FROM deps-dev AS development

# Ortam değişkenlerini ayarla
ENV NODE_ENV=development
ENV PORT=3002

# Kaynak kodunu kopyala
COPY --chown=nodejs:nodejs . .

# Gerekli dizinleri oluştur
RUN mkdir -p uploads/mobile data logs && \
    chown -R nodejs:nodejs uploads data logs

# Kullanıcıyı değiştir
USER nodejs

# Port'ları expose et
EXPOSE 3002
EXPOSE 9229

# Volume mount noktası için
VOLUME ["/app/uploads", "/app/data"]

# Geliştirme modunda çalıştır
CMD ["npm", "run", "dev"]
