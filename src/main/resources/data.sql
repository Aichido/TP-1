-- Compte de test TP2
-- Email    : toto@example.com
-- Password : Toto1234!@secure  (BCrypt, politique TP2 : 12 car, maj, min, chiffre, special)
INSERT IGNORE INTO users (email, password_hash, failed_attempts, created_at)
VALUES ('toto@example.com', '$2a$10$gYVgafi6UHNLf2x7HD8.6eYwXETvQ2WKWOPTkcXzFFDSm13FzL33S', 0, NOW());
