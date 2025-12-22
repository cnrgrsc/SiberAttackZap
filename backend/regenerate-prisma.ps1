# Prisma Client'ı yeniden oluştur
Write-Host "🔄 Prisma Client yenileniyor..." -ForegroundColor Yellow

# Backend dizinine git
Set-Location -Path "C:\Users\caner.guresci\Desktop\Yeni klasör\SiberAttack\backend"

# Prisma Client'ı yeniden oluştur
npx prisma generate

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Prisma Client başarıyla oluşturuldu!" -ForegroundColor Green
} else {
    Write-Host "❌ Prisma Client oluşturulamadı. Backend sunucusunu durdurup tekrar deneyin." -ForegroundColor Red
}

Write-Host ""
Write-Host "Not: Eğer hata alırsanız, backend sunucusunu durdurun (Ctrl+C) ve bu scripti tekrar çalıştırın." -ForegroundColor Cyan
