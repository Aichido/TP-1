-- Compte de test TP3
-- Email    : toto@example.com
-- Password : Toto1234!@secure  (stocké en clair - TP3 pédagogique)
-- TP4 chiffrera ce champ avec AES-GCM + APP_MASTER_KEY
INSERT IGNORE INTO users (email, password_encrypted, failed_attempts, created_at)
VALUES ('toto@example.com', 'Toto1234!@secure', 0, NOW());
