package com.example.auth;

import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires du service d'authentification TP2.
 * Couvre les 10 cas obligatoires + 2 recommandés (non-divulgation, lockout).
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class AuthServiceTest {

    @Autowired
    private AuthService authService;

    private static final String VALID_EMAIL = "test@example.com";
    private static final String VALID_PASSWORD = "ValidPass1!@secure";

    // 1. Email vide
    @Test
    void registerShouldFailWhenEmailIsBlank() {
        assertThrows(InvalidInputException.class,
            () -> authService.register("", VALID_PASSWORD));
    }

    // 2. Format email incorrect
    @Test
    void registerShouldFailWhenEmailFormatIsInvalid() {
        assertThrows(InvalidInputException.class,
            () -> authService.register("notanemail", VALID_PASSWORD));
    }

    // 3. Mot de passe trop court (< 12 caractères)
    @Test
    void registerShouldFailWhenPasswordTooShort() {
        assertThrows(InvalidInputException.class,
            () -> authService.register(VALID_EMAIL, "Short1!"));
    }

    // 4. Mot de passe sans majuscule
    @Test
    void registerShouldFailWhenPasswordHasNoUppercase() {
        assertThrows(InvalidInputException.class,
            () -> authService.register(VALID_EMAIL, "lowercase1!secure"));
    }

    // 5. Inscription réussie
    @Test
    void registerShouldSucceedWithValidData() {
        assertDoesNotThrow(() -> authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    // 6. Inscription refusée si email déjà existant
    @Test
    void registerShouldFailWhenEmailAlreadyExists() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        assertThrows(ResourceConflictException.class,
            () -> authService.register(VALID_EMAIL, VALID_PASSWORD));
    }

    // 7. Login réussi
    @Test
    void loginShouldSucceedWithCorrectCredentials() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        String token = authService.login(VALID_EMAIL, VALID_PASSWORD);
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    // 8. Login KO si mot de passe incorrect
    @Test
    void loginShouldFailWithWrongPassword() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        assertThrows(AuthenticationFailedException.class,
            () -> authService.login(VALID_EMAIL, "WrongPass1!abc"));
    }

    // 9. Login KO si email inconnu
    @Test
    void loginShouldFailWithUnknownEmail() {
        assertThrows(AuthenticationFailedException.class,
            () -> authService.login("unknown@example.com", VALID_PASSWORD));
    }

    // 10. Accès /api/me : refus sans token
    @Test
    void getUserByTokenShouldFailWhenTokenIsNull() {
        assertThrows(AuthenticationFailedException.class,
            () -> authService.getUserByToken(null));
    }

    // 11. Accès /api/me : acceptation après login
    @Test
    void getUserByTokenShouldSucceedAfterLogin() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);
        String token = authService.login(VALID_EMAIL, VALID_PASSWORD);
        assertDoesNotThrow(() -> authService.getUserByToken(token));
    }

    // 12. Non-divulgation : même message pour email inconnu ou mauvais mot de passe
    @Test
    void loginShouldReturnSameMessageForUnknownEmailAndWrongPassword() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);

        AuthenticationFailedException exUnknown = assertThrows(
            AuthenticationFailedException.class,
            () -> authService.login("nobody@example.com", VALID_PASSWORD)
        );
        AuthenticationFailedException exWrongPwd = assertThrows(
            AuthenticationFailedException.class,
            () -> authService.login(VALID_EMAIL, "WrongPass1!abc")
        );

        assertEquals(exUnknown.getMessage(), exWrongPwd.getMessage());
    }

    // 13. Lockout après 5 échecs consécutifs
    @Test
    void loginShouldLockAccountAfterFiveFailedAttempts() {
        authService.register(VALID_EMAIL, VALID_PASSWORD);

        for (int i = 0; i < AuthService.MAX_FAILED_ATTEMPTS; i++) {
            try {
                authService.login(VALID_EMAIL, "WrongPass1!abc");
            } catch (AuthenticationFailedException ignored) {
                // attendu
            }
        }

        assertThrows(AccountLockedException.class,
            () -> authService.login(VALID_EMAIL, VALID_PASSWORD));
    }
}
