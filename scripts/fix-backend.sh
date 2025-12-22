#!/bin/bash

echo "🛠️ Backend sorunlarını çözme scripti..."

echo "📦 Backend container'ını durduruyorum..."
docker stop siberzed-backend || true
docker rm siberzed-backend || true

echo "🏗️ Backend imajını yeniden build ediyorum..."
docker-compose build --no-cache backend

echo "🚀 Tüm servisleri yeniden başlatıyorum..."
docker-compose up -d

echo "⏳ 30 saniye bekliyorum..."
sleep 30

echo "🔍 Servis durumlarını kontrol ediyorum..."
docker-compose ps

echo "📋 Backend loglarını gösteriyorum..."
docker logs siberzed-backend --tail 20

echo "✅ İşlem tamamlandı!"
