-- Granüler izinler için yeni Permission kayıtları ekle

-- WEB TARAMA İZİNLERİ (Otomatik/Manuel)
INSERT INTO "permissions" ("id", "name", "category", "displayName", "description")
VALUES 
  (gen_random_uuid(), 'SCAN_WEB_CREATE', 'SCAN_MANAGEMENT', 'Web Tarama Başlatma', 'Web uygulaması taraması başlatabilir'),
  (gen_random_uuid(), 'SCAN_WEB_VIEW', 'SCAN_MANAGEMENT', 'Web Tarama Görüntüleme', 'Web taramalarını görüntüleyebilir'),
  (gen_random_uuid(), 'SCAN_WEB_DELETE', 'SCAN_MANAGEMENT', 'Web Tarama Silme', 'Web taramalarını silebilir'),
  (gen_random_uuid(), 'SCAN_WEB_CONTROL', 'SCAN_MANAGEMENT', 'Web Tarama Kontrolü', 'Web taramasını durdur/devam ettir/duraklat'),
  
  -- MOBİL TARAMA İZİNLERİ
  (gen_random_uuid(), 'SCAN_MOBILE_CREATE', 'SCAN_MANAGEMENT', 'Mobil Tarama Başlatma', 'Mobil uygulama taraması başlatabilir'),
  (gen_random_uuid(), 'SCAN_MOBILE_VIEW', 'SCAN_MANAGEMENT', 'Mobil Tarama Görüntüleme', 'Mobil taramalarını görüntüleyebilir'),
  (gen_random_uuid(), 'SCAN_MOBILE_DELETE', 'SCAN_MANAGEMENT', 'Mobil Tarama Silme', 'Mobil taramalarını silebilir'),
  
  -- RAPOR İZİNLERİ
  (gen_random_uuid(), 'REPORT_EMAIL_SEND', 'REPORT_MANAGEMENT', 'Rapor Email Gönderme', 'Raporları email ile gönderebilir'),
  (gen_random_uuid(), 'REPORT_EMAIL_AUTO', 'REPORT_MANAGEMENT', 'Otomatik Email Ayarı', 'Otomatik email gönderimini ayarlayabilir'),
  
  -- TARAMA GEÇMİŞİ İZİNLERİ
  (gen_random_uuid(), 'SCAN_HISTORY_VIEW_OWN', 'SCAN_MANAGEMENT', 'Kendi Geçmişini Görme', 'Kendi tarama geçmişini görebilir'),
  (gen_random_uuid(), 'SCAN_HISTORY_VIEW_ALL', 'SCAN_MANAGEMENT', 'Tüm Geçmişi Görme', 'Tüm kullanıcıların tarama geçmişini görebilir')
ON CONFLICT (name) DO NOTHING;

-- Eski genel izinleri kaldır (SCAN_CREATE gibi)
-- Bunlar artık daha spesifik izinlerle değiştirildi
