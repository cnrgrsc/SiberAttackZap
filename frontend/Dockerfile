# Frontend için optimize edilmiş çok aşamalı Dockerfile
FROM node:20-bullseye-slim AS base

# Çalışma dizinini ayarla
WORKDIR /app

# Kullanıcı oluştur
RUN groupadd -g 1001 react || true && \
    useradd -u 1001 -g 1001 -M -s /bin/false react || true

# Bağımlılıklar aşaması
FROM base AS deps
COPY package*.json ./

# npm ci kullanarak tutarlı ve tam kurulum garanti et
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN npm config set strict-ssl false && \
    npm ci --no-audit --no-fund && \
    npm cache clean --force

# Build aşaması  
FROM base AS builder
ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

# Allow passing the API URL at build time (REACT reads env vars at build time)
ARG REACT_APP_API_URL
ENV REACT_APP_API_URL=${REACT_APP_API_URL}

# Node Options - RAM kullanımını optimize et
ARG NODE_OPTIONS
ENV NODE_OPTIONS=${NODE_OPTIONS:-"--max-old-space-size=1536"}

# Build optimizasyonları
ENV GENERATE_SOURCEMAP=false
ENV DISABLE_ESLINT_PLUGIN=true
ENV TSC_COMPILE_ON_ERROR=true

# Copy package.json and lockfile from deps stage, then (re)install deps
# Installing in the builder stage ensures node_modules/.bin (e.g. react-scripts)
# are present when we run `npm run build`. This keeps the deps stage for
# caching but guarantees the builder has the executable bins.
COPY --from=deps --chown=react:react /app/package*.json ./

# Reinstall dependencies in builder to ensure all bins are available
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN npm config set strict-ssl false && \
    npm ci --no-audit --no-fund && \
    npm cache clean --force

# Kaynak kodunu kopyala
COPY --chown=react:react . .

# Debug: node/npm and node_modules checks
# Print node and npm versions, show whether react-scripts is installed and list node_modules/.bin
RUN node -v && npm -v && npm ls react-scripts --depth=0 || true && \
    echo "--- node_modules listing ---" && ls -la node_modules || true && \
    echo "--- node_modules/.bin listing ---" && ls -la node_modules/.bin || echo "node_modules/.bin bulunamadı"

# React uygulamasını build et
RUN npm run build

# Geliştirme aşaması
FROM deps AS development
ENV NODE_ENV=development

# Kaynak kodunu kopyala
COPY --chown=react:react . .

# Kullanıcıyı değiştir
USER react

# Port'u expose et
EXPOSE 3000

# Volume mount noktası
VOLUME ["/app/src", "/app/public"]

# Geliştirme modunda çalıştır
CMD ["npm", "start"]

# Üretim aşaması
FROM nginx:alpine AS production

# Nginx kullanıcısı oluştur (Alpine busybox komutları kullan)
RUN addgroup -g 1001 -S nginx-custom || true && \
    adduser -u 1001 -G nginx-custom -S -s /bin/false nginx-custom || true

# Build'den static dosyaları kopyala
COPY --from=builder /app/build /usr/share/nginx/html

# Nginx konfigürasyon dosyasını kopyala
COPY nginx.conf /etc/nginx/nginx.conf

# Create nginx cache/log/run directories and set ownership so the entrypoint
# can create required temp files even when nginx later drops privileges.
RUN mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/fastcgi_temp /var/cache/nginx/proxy_temp /var/cache/nginx/uwsgi_temp /var/cache/nginx/scgi_temp /var/log/nginx /var/run && \
    chown -R nginx-custom:nginx-custom /var/cache/nginx /var/log/nginx /var/run /usr/share/nginx/html


# Port'u expose et
EXPOSE 3001

# Health check ekle (curl nginx:alpine'da mevcut)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3001/ || exit 1

# Nginx'i başlat
CMD ["nginx", "-g", "daemon off;"]