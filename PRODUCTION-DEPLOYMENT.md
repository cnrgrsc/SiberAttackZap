# 🚀 SiberZed Production Deployment Guide

## 📋 Sunucu Bilgileri
- **IP Adresi:** 10.5.63.219
- **Frontend URL:** http://10.5.63.219:5002
- **Backend URL:** http://10.5.63.219:5001
- **ZAP Proxy:** http://10.5.63.219:8080
- **MobSF:** http://10.5.63.219:5003

## ✅ Yapılan Değişiklikler

### 1. Frontend Environment Variables
**Düzenlenen Dosyalar:**
- ✅ `frontend/.env.production` - Production ortamı için oluşturuldu
- ✅ `frontend/src/services/api.ts` - localhost:5001 (development default)
- ✅ `frontend/src/services/authService.ts` - localhost:5001 (development default)
- ✅ `frontend/src/services/mobsfService.ts` - localhost:5001 (development default)
- ✅ `frontend/src/services/socketService.ts` - localhost:5001 (development default)
- ✅ `frontend/src/components/Scan/AutomatedScan.tsx` - Tüm localhost:5002 → localhost:5001

**Environment Variables:**
```properties
REACT_APP_API_URL=http://10.5.63.219:5001
REACT_APP_ZAP_URL=http://10.5.63.219:8080
REACT_APP_MOBSF_URL=http://10.5.63.219:8000
PORT=3001
```

### 2. Backend CORS Configuration
Backend zaten dinamik CORS yapılandırmasına sahip:
- İç ağ IP aralıklarını otomatik kabul eder (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Production modunda sadece güvenli origin'lere izin verir

### 3. Docker Configuration
**Root `.env` dosyası zaten production için hazır:**
```properties
NODE_ENV=production
CORS_ORIGIN="http://10.5.63.219:5002"
BACKEND_PORT=5001
REACT_APP_API_URL="http://10.5.63.219:5001"
ZAP_PROXY_URL="http://10.5.63.219:8080"
MOBSF_BASE_URL="http://10.5.63.219:5003"
```

## 🔧 Deployment Adımları

### Adım 1: Build Frontend (Production)
```bash
cd /home/caner.guresci/SiberAttack/frontend
NODE_ENV=production npm run build
```

### Adım 2: Docker Image'lerini Yeniden Build Et
```bash
cd /home/caner.guresci/SiberAttack

# Frontend image'ini yeniden build et (production target)
docker-compose build --no-cache frontend

# Backend image'ini yeniden build et (production target)
docker-compose build --no-cache backend
```

### Adım 3: Container'ları Restart Et
```bash
# Eski container'ları durdur
docker-compose down

# Yeni container'ları başlat
docker-compose up -d

# Logları kontrol et
docker-compose logs -f frontend
docker-compose logs -f backend
```

### Adım 4: Health Check
```bash
# Backend health check
curl http://10.5.63.219:5001/health

# Frontend health check
curl http://10.5.63.219:5002/health

# Container durumlarını kontrol et
docker ps
```

## 🧪 Test Adımları

### 1. Frontend'e Erişim Testi
```bash
# Tarayıcıda aç:
http://10.5.63.219:5002
```

### 2. Backend API Testi
```bash
curl http://10.5.63.219:5001/api/health
```

### 3. WebSocket Bağlantısı Testi
- Frontend'de bir tarama başlat
- Tarama ilerlemesinin real-time güncellendiğini kontrol et
- Browser Console'da Socket.IO bağlantı mesajlarını kontrol et

### 4. CORS Testi
- Browser Developer Tools > Network sekmesi
- Herhangi bir API isteği yap
- Response Headers'da `Access-Control-Allow-Origin: http://10.5.63.219:5002` olduğunu kontrol et

## 📊 Port Mapping

| Servis | Internal Port | External Port | URL |
|--------|--------------|---------------|-----|
| Frontend | 3001 | 5002 | http://10.5.63.219:5002 |
| Backend | 5001 | 5001 | http://10.5.63.219:5001 |
| ZAP Proxy | 8080 | 8080 | http://10.5.63.219:8080 |
| MobSF | 5003 | 5003 | http://10.5.63.219:5003 |

## 🔍 Troubleshooting

### Frontend Backend'e Bağlanamıyor
```bash
# Frontend container içinde environment variable'ları kontrol et
docker exec -it siberzed-frontend sh
printenv | grep REACT_APP

# Beklenen çıktı:
# REACT_APP_API_URL=http://10.5.63.219:5001
```

### CORS Hataları
```bash
# Backend loglarını kontrol et
docker-compose logs backend | grep -i cors

# Backend .env dosyasını kontrol et
cat .env | grep CORS_ORIGIN
# Beklenen: CORS_ORIGIN="http://10.5.63.219:5002"
```

### WebSocket Bağlantı Sorunları
```bash
# Backend Socket.IO loglarını kontrol et
docker-compose logs backend | grep -i socket

# Frontend browser console'da:
# "WebSocket connection established" mesajını kontrol et
```

## 📝 Önemli Notlar

1. **Build Time vs Runtime:**
   - React environment variables BUILD zamanında embed edilir
   - Her değişiklikten sonra `npm run build` gereklidir
   - Docker build'de `--no-cache` kullanın

2. **Environment Dosyaları:**
   - `frontend/.env` → Development (localhost)
   - `frontend/.env.production` → Production (10.5.63.219)
   - Root `.env` → Docker compose için

3. **CORS:**
   - Backend otomatik olarak iç ağ IP'lerini kabul eder
   - `CORS_ORIGIN` değişkenini değiştirirseniz backend'i restart edin

4. **Health Checks:**
   - Frontend: `http://10.5.63.219:5002/health`
   - Backend: `http://10.5.63.219:5001/health`

## 🎯 Deployment Checklist

- [x] Frontend environment variables güncellendi
- [x] Backend CORS configuration kontrol edildi
- [x] Docker-compose.yml production için hazır
- [x] .env dosyası production IP'leriyle güncellendi
- [ ] Frontend production build yapıldı
- [ ] Docker images yeniden build edildi
- [ ] Container'lar restart edildi
- [ ] Health check başarılı
- [ ] Frontend'e tarayıcıdan erişim test edildi
- [ ] Backend API test edildi
- [ ] WebSocket bağlantısı test edildi
- [ ] Bir tarama başlatıldı ve başarıyla tamamlandı

## 🚀 Quick Deploy Script

Aşağıdaki komutu sunucuda çalıştırın:

```bash
#!/bin/bash
cd /home/caner.guresci/SiberAttack

echo "🔄 Stopping containers..."
docker-compose down

echo "🏗️ Building production images..."
docker-compose build --no-cache frontend backend

echo "🚀 Starting containers..."
docker-compose up -d

echo "⏳ Waiting for services to be healthy..."
sleep 30

echo "✅ Checking container status..."
docker ps

echo "🧪 Running health checks..."
curl -f http://10.5.63.219:5001/health && echo "✅ Backend healthy"
curl -f http://10.5.63.219:5002/health && echo "✅ Frontend healthy"

echo "📋 Viewing logs..."
docker-compose logs --tail=50
```

---
**Son Güncelleme:** 27 Ekim 2025
**Hazırlayan:** GitHub Copilot
