package com.example.auth;

import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import com.example.auth.service.HmacService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests d'intégration du service d'authentification.
 * TP3 : HMAC, anti-rejeu, timestamp, token SSO (15 cas).
 * TP5 : changement de mot de passe (7 cas supplémentaires).
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class AuthServiceTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private HmacService hmacService;

    private static final String VALID_EMAIL = "test@example.com";
    private static final String VALID_PASSWORD = "ValidPass1!@secure";

    // ── Helpers ──────────────────────────────────────────────────────────────

    private String nonce() { return UUID.randomUUID().toString(); }

    private long nowTs() { return Instant.now().getEpochSecond(); }

    private String validHmac(String email, String nonce, long ts) {
        return hmacService.compute(VALID_PASSWORD,
            hmacService.buildMessage(email, nonce, ts));
    }

    private String loginOk() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        String n = nonce(); long ts = nowTs();
        return authService.login(VALID_EMAIL, n, ts, validHmac(VALID_EMAIL, n, ts));
    }

    // ── 1. Inscription valide ────────────────────────────────────────────────
    @Test
    void registerShouldSucceedWithValidData() {
        assertDoesNotThrow(() -> authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    // ── 2. Email vide ────────────────────────────────────────────────────────
    @Test
    void registerShouldFailWhenEmailIsBlank() {
        assertThrows(InvalidInputException.class,
            () -> authService.register("", VALID_PASSWORD));
    }

    // ── 3. Format email incorrect ────────────────────────────────────────────
    @Test
    void registerShouldFailWhenEmailFormatIsInvalid() {
        assertThrows(InvalidInputException.class,
            () -> authService.register("notanemail", VALID_PASSWORD));
    }

    // ── 4. Mot de passe trop court ───────────────────────────────────────────
    @Test
    void registerShouldFailWhenPasswordTooShort() {
        assertThrows(InvalidInputException.class,
            () -> authService.register(VALID_EMAIL, "Short1!"));
    }

    // ── 5. Email déjà existant ───────────────────────────────────────────────
    @Test
    void registerShouldFailWhenEmailAlreadyExists() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        assertThrows(ResourceConflictException.class,
            () -> authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    // ── 6. Login OK avec HMAC valide ─────────────────────────────────────────
    @Test
    void loginShouldSucceedWithValidHmac() {
        String token = loginOk();
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    // ── 7. Login KO - HMAC invalide ──────────────────────────────────────────
    @Test
    void loginShouldFailWithInvalidHmac() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        String n = nonce(); long ts = nowTs();
        assertThrows(AuthenticationFailedException.class,
            () -> authService.login(VALID_EMAIL, n, ts, "invalid_hmac_value"));
    }

    // ── 8. Login KO - timestamp expiré (> 60 s dans le passé) ────────────────
    @Test
    void loginShouldFailWithExpiredTimestamp() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        String n = nonce();
        long expiredTs = Instant.now().getEpochSecond() - 120L; // 2 min dans le passé
        String hmac = validHmac(VALID_EMAIL, n, expiredTs);
        assertThrows(AuthenticationFailedException.class,
            () -> authService.login(VALID_EMAIL, n, expiredTs, hmac));
    }

    // ── 9. Login KO - timestamp dans le futur (> 60 s) ───────────────────────
    @Test
    void loginShouldFailWithFutureTimestamp() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        String n = nonce();
        long futureTs = Instant.now().getEpochSecond() + 120L; // 2 min dans le futur
        String hmac = validHmac(VALID_EMAIL, n, futureTs);
        assertThrows(AuthenticationFailedException.class,
            () -> authService.login(VALID_EMAIL, n, futureTs, hmac));
    }

    // ── 10. Login KO - nonce déjà utilisé ────────────────────────────────────
    @Test
    void loginShouldFailWhenNonceAlreadyUsed() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        String n = nonce(); long ts = nowTs();
        String hmac = validHmac(VALID_EMAIL, n, ts);

        authService.login(VALID_EMAIL, n, ts, hmac); // premier login OK

        // Deuxième login avec même nonce doit échouer
        long ts2 = nowTs();
        String hmac2 = validHmac(VALID_EMAIL, n, ts2);
        assertThrows(AuthenticationFailedException.class,
            () -> authService.login(VALID_EMAIL, n, ts2, hmac2));
    }

    // ── 11. Login KO - utilisateur inconnu ────────────────────────────────────
    @Test
    void loginShouldFailWithUnknownUser() {
        String n = nonce(); long ts = nowTs();
        String hmac = hmacService.compute("somepass",
            hmacService.buildMessage("nobody@example.com", n, ts));
        assertThrows(AuthenticationFailedException.class,
            () -> authService.login("nobody@example.com", n, ts, hmac));
    }

    // ── 12. Comparaison en temps constant ─────────────────────────────────────
    @Test
    void compareConstantTimeShouldReturnTrueForEqualStrings() {
        assertTrue(hmacService.compareConstantTime("abc", "abc"));
    }

    @Test
    void compareConstantTimeShouldReturnFalseForDifferentStrings() {
        assertFalse(hmacService.compareConstantTime("abc", "xyz"));
    }

    // ── 13. Token émis et accès /api/me OK ───────────────────────────────────
    @Test
    void getUserByTokenShouldSucceedAfterLogin() {
        String token = loginOk();
        assertDoesNotThrow(() -> authService.getUserByToken(token));
    }

    // ── 14. Accès /api/me sans token → refus ─────────────────────────────────
    @Test
    void getUserByTokenShouldFailWhenTokenIsNull() {
        assertThrows(AuthenticationFailedException.class,
            () -> authService.getUserByToken(null));
    }

    // ── 15. HMAC déterministe (même clé + même message = même résultat) ───────
    @Test
    void hmacShouldBeDeterministic() {
        String msg = "email@test.com:nonce-abc:1234567890";
        String h1 = hmacService.compute(VALID_PASSWORD, msg);
        String h2 = hmacService.compute(VALID_PASSWORD, msg);
        assertEquals(h1, h2);
    }

    // ══ TP5 — Changement de mot de passe ══════════════════════════════════════

    private static final String NEW_PASSWORD = "NewSecure2!@strong";

    /** Helper : inscrit l'utilisateur, se connecte et retourne le token SSO. */
    private String registerAndLogin() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        String n = nonce(); long ts = nowTs();
        return authService.login(VALID_EMAIL, n, ts, validHmac(VALID_EMAIL, n, ts));
    }

    /** Helper : HMAC de l'ancien mot de passe pour le changement. */
    private String changeHmac(String email, String n, long ts) {
        return hmacService.compute(VALID_PASSWORD,
            hmacService.buildMessage(email, n, ts));
    }

    // ── 17. Changement OK ─────────────────────────────────────────────────────
    @Test
    void changePasswordShouldSucceedWithValidHmac() {
        String token = registerAndLogin();
        String n = nonce(); long ts = nowTs();
        assertDoesNotThrow(() ->
            authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), NEW_PASSWORD));
    }

    // ── 18. Token invalidé après changement (force reconnexion) ──────────────
    @Test
    void changePasswordShouldInvalidateSessionToken() {
        String token = registerAndLogin();
        String n = nonce(); long ts = nowTs();
        authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), NEW_PASSWORD);
        assertThrows(AuthenticationFailedException.class,
            () -> authService.getUserByToken(token));
    }

    // ── 19. HMAC invalide → refus ─────────────────────────────────────────────
    @Test
    void changePasswordShouldFailWithInvalidHmac() {
        String token = registerAndLogin();
        String n = nonce(); long ts = nowTs();
        assertThrows(AuthenticationFailedException.class,
            () -> authService.changePassword(token, n, ts, "bad_hmac", NEW_PASSWORD));
    }

    // ── 20. Nouveau mot de passe trop court → refus ───────────────────────────
    @Test
    void changePasswordShouldFailWhenNewPasswordTooShort() {
        String token = registerAndLogin();
        String n = nonce(); long ts = nowTs();
        assertThrows(InvalidInputException.class,
            () -> authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), "Short1!"));
    }

    // ── 21. Timestamp expiré → refus ─────────────────────────────────────────
    @Test
    void changePasswordShouldFailWithExpiredTimestamp() {
        String token = registerAndLogin();
        String n = nonce();
        long expiredTs = Instant.now().getEpochSecond() - 120L;
        assertThrows(AuthenticationFailedException.class,
            () -> authService.changePassword(token, n, expiredTs,
                changeHmac(VALID_EMAIL, n, expiredTs), NEW_PASSWORD));
    }

    // ── 22. Nonce déjà utilisé → refus ───────────────────────────────────────
    @Test
    void changePasswordShouldFailWhenNonceAlreadyUsed() {
        String token = registerAndLogin();
        String n = nonce(); long ts = nowTs();
        authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), NEW_PASSWORD);

        // Réinscription pour obtenir un nouveau token et tester la réutilisation du nonce
        authService.register("other@example.com", "OtherPass1!@secure");
        String n2 = nonce(); long ts2 = nowTs();
        String token2 = authService.login("other@example.com", n2, ts2,
            hmacService.compute("OtherPass1!@secure", hmacService.buildMessage("other@example.com", n2, ts2)));

        // Réutilise le nonce déjà consommé
        long ts3 = nowTs();
        String hmac3 = hmacService.compute("OtherPass1!@secure",
            hmacService.buildMessage("other@example.com", n, ts3));
        assertThrows(AuthenticationFailedException.class,
            () -> authService.changePassword(token2, n, ts3, hmac3, NEW_PASSWORD));
    }

    // ── 23. Token invalide → refus ────────────────────────────────────────────
    @Test
    void changePasswordShouldFailWithInvalidToken() {
        String n = nonce(); long ts = nowTs();
        assertThrows(AuthenticationFailedException.class,
            () -> authService.changePassword("invalid-token", n, ts, "hmac", NEW_PASSWORD));
    }

    // ── 24. Login avec nouveau mot de passe après changement ─────────────────
    @Test
    void loginShouldSucceedWithNewPasswordAfterChange() {
        String token = registerAndLogin();
        String n = nonce(); long ts = nowTs();
        authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), NEW_PASSWORD);

        // Connexion avec le nouveau mot de passe
        String n2 = nonce(); long ts2 = nowTs();
        String newHmac = hmacService.compute(NEW_PASSWORD,
            hmacService.buildMessage(VALID_EMAIL, n2, ts2));
        String newToken = authService.login(VALID_EMAIL, n2, ts2, newHmac);
        assertNotNull(newToken);
    }

    // ── 16. Verrouillage après 5 échecs ──────────────────────────────────────
    @Test
    void loginShouldLockAccountAfterFiveFailedAttempts() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);

        for (int i = 0; i < AuthService.MAX_FAILED_ATTEMPTS; i++) {
            try {
                String n = nonce(); long ts = nowTs();
                authService.login(VALID_EMAIL, n, ts, "bad_hmac");
            } catch (AuthenticationFailedException ignored) {}
        }

        String n = nonce(); long ts = nowTs();
        String goodHmac = validHmac(VALID_EMAIL, n, ts);
        assertThrows(AccountLockedException.class,
            () -> authService.login(VALID_EMAIL, n, ts, goodHmac));
    }
}
