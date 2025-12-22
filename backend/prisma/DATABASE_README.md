# Prisma Database Protection

Bu klasördeki `dev.db` dosyası SQLite veritabanıdır.

## ⚠️ UYARI

**BU DOSYAYI SİLMEYİN!**

- Bu dosya tüm kullanıcı, rol ve izin verilerini içerir.
- Silinirse tüm veriler kaybolur.

## Backup Önerisi

Veritabanını düzenli olarak yedekleyin:

```powershell
Copy-Item "dev.db" "dev.db.backup"
```
