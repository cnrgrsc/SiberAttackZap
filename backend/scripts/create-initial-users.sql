-- Create initial admin and test users
-- NO PASSWORDS STORED - LDAP will handle authentication

-- Admin user
INSERT INTO users (id, username, "firstName", "lastName", email, role, department, "isActive", "ldapVerified", "createdAt", "updatedAt")
VALUES (
  'admin-001',
  'caner.guresci',
  'Caner',
  'Güresci',
  'caner.guresci@ibb.gov.tr',
  'admin',
  'IT',
  true,
  false,
  NOW(),
  NOW()
)
ON CONFLICT (username) DO UPDATE SET
  role = 'admin',
  "isActive" = true;

-- Developer user (example)
INSERT INTO users (id, username, "firstName", "lastName", email, role, department, "isActive", "ldapVerified", "createdAt", "updatedAt")
VALUES (
  'dev-001',
  'test.user',
  'Test',
  'User',
  'test.user@ibb.gov.tr',
  'developer',
  'IT',
  true,
  false,
  NOW(),
  NOW()
)
ON CONFLICT (username) DO NOTHING;

-- Show created users
SELECT username, role, "isActive", "ldapVerified" FROM users ORDER BY "createdAt" DESC LIMIT 10;
