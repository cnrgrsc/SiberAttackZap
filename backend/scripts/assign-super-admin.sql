-- SUPER_ADMIN rolünü caner.guresci@ibb.gov.tr kullanıcısına ata
-- Bu script PostgreSQL'de çalıştırılmalıdır

-- 1. Önce kullanıcı ve rol ID'lerini kontrol et
SELECT 
    u.id as user_id,
    u.email,
    u."firstName",
    u."lastName"
FROM users u
WHERE u.email = 'caner.guresci@ibb.gov.tr';

-- 2. SUPER_ADMIN rol ID'sini bul
SELECT id, name, "displayName" 
FROM roles 
WHERE name = 'SUPER_ADMIN';

-- 3. Mevcut rolleri kontrol et
SELECT 
    u.email,
    r.name as role_name,
    r."displayName",
    ur."assignedAt"
FROM user_roles ur
JOIN users u ON ur."userId" = u.id
JOIN roles r ON ur."roleId" = r.id
WHERE u.email = 'caner.guresci@ibb.gov.tr';

-- 4. SUPER_ADMIN rolünü ekle (eğer yoksa)
INSERT INTO user_roles ("userId", "roleId", "assignedBy", "assignedAt")
SELECT 
    u.id,
    r.id,
    u.id,  -- Kendi kendine atanmış gibi
    NOW()
FROM users u, roles r
WHERE u.email = 'caner.guresci@ibb.gov.tr'
  AND r.name = 'SUPER_ADMIN'
  AND NOT EXISTS (
    SELECT 1 FROM user_roles ur2
    WHERE ur2."userId" = u.id AND ur2."roleId" = r.id
  );

-- 5. Sonucu doğrula
SELECT 
    u.email,
    u."firstName",
    u."lastName",
    r.name as role_name,
    r."displayName",
    COUNT(rp.id) as permission_count
FROM user_roles ur
JOIN users u ON ur."userId" = u.id
JOIN roles r ON ur."roleId" = r.id
LEFT JOIN role_permissions rp ON r.id = rp."roleId"
WHERE u.email = 'caner.guresci@ibb.gov.tr'
GROUP BY u.email, u."firstName", u."lastName", r.name, r."displayName";

-- 6. Kullanıcının tüm izinlerini listele
SELECT DISTINCT
    p.name as permission_name,
    p."displayName",
    p.category
FROM user_roles ur
JOIN roles r ON ur."roleId" = r.id
JOIN role_permissions rp ON r.id = rp."roleId"
JOIN permissions p ON rp."permissionId" = p.id
WHERE ur."userId" IN (
    SELECT id FROM users WHERE email = 'caner.guresci@ibb.gov.tr'
)
ORDER BY p.category, p.name;
