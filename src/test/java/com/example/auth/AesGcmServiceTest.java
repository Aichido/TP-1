package com.example.auth;

import com.example.auth.exception.EncryptionException;
import com.example.auth.service.AesGcmService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires du service AES-GCM (TP4).
 * Ces tests vérifient le chiffrement/déchiffrement sans contexte Spring.
 * Couvre les 4 cas obligatoires liés à la Master Key + tests supplémentaires.
 */
class AesGcmServiceTest {

    private AesGcmService service;

    @BeforeEach
    void setUp() {
        service = new AesGcmService("test_master_key_for_unit_tests");
    }

    // ── 1. Round-trip : chiffrement → déchiffrement = texte original ──────────
    @Test
    void encryptDecryptShouldReturnOriginalPassword() {
        String plain = "ValidPass1!@secure";
        assertEquals(plain, service.decrypt(service.encrypt(plain)));
    }

    // ── 2. Le chiffré est différent du texte en clair ─────────────────────────
    @Test
    void encryptedPasswordShouldDifferFromPlaintext() {
        String plain = "ValidPass1!@secure";
        String encrypted = service.encrypt(plain);
        assertNotEquals(plain, encrypted);
        assertTrue(encrypted.startsWith("v1:"), "Le format doit commencer par 'v1:'");
    }

    // ── 3. Déchiffrement KO si le chiffré est modifié (intégrité GCM) ────────
    @Test
    void decryptShouldFailWithTamperedCiphertext() {
        String encrypted = service.encrypt("password123");
        String[] parts = encrypted.split(":", 3);

        // Modifier le dernier octet du ciphertext (invalide le tag GCM)
        byte[] ctBytes = Base64.getDecoder().decode(parts[2]);
        ctBytes[ctBytes.length - 1] ^= 0xFF;
        String tampered = parts[0] + ":" + parts[1] + ":"
            + Base64.getEncoder().encodeToString(ctBytes);

        assertThrows(EncryptionException.class, () -> service.decrypt(tampered));
    }

    // ── 4. Démarrage KO si APP_MASTER_KEY absente ─────────────────────────────
    @Test
    void constructionShouldFailWithBlankKey() {
        assertThrows(IllegalStateException.class, () -> new AesGcmService(""));
        assertThrows(IllegalStateException.class, () -> new AesGcmService("   "));
    }

    // ── 5. IV aléatoire : même clair → chiffrés différents à chaque appel ─────
    @Test
    void encryptShouldProduceDifferentCiphertextEachTime() {
        String plain = "SamePassword1!@x";
        String enc1 = service.encrypt(plain);
        String enc2 = service.encrypt(plain);
        assertNotEquals(enc1, enc2, "Deux chiffrements du même texte doivent être différents (IV aléatoire)");
        // Les deux doivent néanmoins déchiffrer correctement
        assertEquals(plain, service.decrypt(enc1));
        assertEquals(plain, service.decrypt(enc2));
    }

    // ── 6. Format invalide → EncryptionException ──────────────────────────────
    @Test
    void decryptShouldFailWithInvalidFormat() {
        assertThrows(EncryptionException.class, () -> service.decrypt("not-encrypted-at-all"));
        assertThrows(EncryptionException.class, () -> service.decrypt(null));
        assertThrows(EncryptionException.class, () -> service.decrypt("v1:onlyonepart"));
    }
}
