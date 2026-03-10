package com.example.auth;

import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires du service d'authentification.
 * Minimum 8 tests requis par le cahier des charges TP1.
 */
@SpringBootTest
@Transactional  // Chaque test est rollback automatiquement
class AuthServiceTest {

    @Autowired
    private AuthService authService;

    // --- Test 1 : Validation email vide ---
    @Test
    void testRegister_EmailVide_ThrowsInvalidInput() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("", "motdepasse"));
    }

    // --- Test 2 : Validation format email incorrect ---
    @Test
    void testRegister_EmailFormatInvalide_ThrowsInvalidInput() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("pasunemail", "motdepasse"));
    }

    // --- Test 3 : Mot de passe trop court ---
    @Test
    void testRegister_MotDePasseTropCourt_ThrowsInvalidInput() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@test.com", "abc"));
    }

    // --- Test 4 : Inscription réussie ---
    @Test
    void testRegister_OK() {
        var user = authService.register("nouveau@test.com", "abcd");
        assertNotNull(user.getId());
        assertEquals("nouveau@test.com", user.getEmail());
    }

    // --- Test 5 : Inscription refusée si email déjà existant ---
    @Test
    void testRegister_EmailDeja_ThrowsConflict() {
        authService.register("doublon@test.com", "abcd");
        assertThrows(ResourceConflictException.class, () ->
                authService.register("doublon@test.com", "autrepwd"));
    }

    // --- Test 6 : Login réussi ---
    @Test
    void testLogin_OK() {
        authService.register("login@test.com", "abcd");
        String token = authService.login("login@test.com", "abcd");
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    // --- Test 7 : Login KO si mot de passe incorrect ---
    @Test
    void testLogin_MauvaisMotDePasse_ThrowsAuthFailed() {
        authService.register("wrong@test.com", "bonpwd");
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("wrong@test.com", "mauvais"));
    }

    // --- Test 8 : Login KO si email inconnu ---
    @Test
    void testLogin_EmailInconnu_ThrowsAuthFailed() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@test.com", "nimporte"));
    }

    // --- Test 9 : Accès /api/me refusé sans token ---
    @Test
    void testGetMe_SansToken_ThrowsAuthFailed() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.getUserByToken(null));
    }

    // --- Test 10 : Accès /api/me accepté après login ---
    @Test
    void testGetMe_ApresLogin_OK() {
        authService.register("me@test.com", "abcd");
        String token = authService.login("me@test.com", "abcd");
        var user = authService.getUserByToken(token);
        assertEquals("me@test.com", user.getEmail());
    }
}