package com.example.auth.controller;

import com.example.auth.dto.ChangePasswordRequest;
import com.example.auth.dto.LoginHmacRequest;
import com.example.auth.dto.LoginHmacResponse;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Contrôleur REST pour l'authentification.
 * <p>
 * TP3 : Le login utilise désormais le protocole HMAC.
 * Le client envoie {@code {email, nonce, timestamp, hmac}} au lieu de {@code {email, password}}.
 * </p>
 * Endpoints :
 * <ul>
 *   <li>POST /api/auth/register         — inscription</li>
 *   <li>POST /api/auth/login            — connexion HMAC</li>
 *   <li>POST /api/auth/change-password  — changement de mot de passe (TP5)</li>
 *   <li>GET  /api/me                    — profil (Bearer token requis)</li>
 * </ul>
 *
 * @author Tahiry
 * @version 5.0 - TP5
 */
@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Inscription d'un nouvel utilisateur.
     * @param request corps JSON avec email et password
     * @return 201 Created si succès
     */
    @PostMapping("/api/auth/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequest request) {
        authService.register(request.getEmail(), request.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "Utilisateur créé avec succès"));
    }

    /**
     * Connexion via protocole HMAC (TP3).
     * <p>
     * Payload attendu : {@code {email, nonce, timestamp, hmac}}<br>
     * Retourne un token SSO valide 15 minutes.
     * </p>
     * @param request corps JSON avec email, nonce, timestamp, hmac
     * @return 200 OK avec accessToken et expiresAt
     */
    @PostMapping("/api/auth/login")
    public ResponseEntity<LoginHmacResponse> login(@RequestBody LoginHmacRequest request) {
        String token = authService.login(
            request.getEmail(),
            request.getNonce(),
            request.getTimestamp(),
            request.getHmac()
        );
        String expiresAt = LocalDateTime.now().plusMinutes(15).toString();
        return ResponseEntity.ok(new LoginHmacResponse(token, expiresAt, "Connexion réussie"));
    }

    /**
     * Changement de mot de passe authentifié (TP5).
     * <p>
     * L'utilisateur prouve la connaissance de son ancien mot de passe via un HMAC,
     * puis fournit le nouveau mot de passe. Le token SSO est invalidé après succès
     * pour forcer une reconnexion.
     * </p>
     * @param authorization header "Bearer {token}"
     * @param request       corps JSON avec nonce, timestamp, oldHmac, newPassword
     * @return 200 OK avec message de confirmation
     */
    @PostMapping("/api/auth/change-password")
    public ResponseEntity<Map<String, String>> changePassword(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody ChangePasswordRequest request) {
        String token = extractToken(authorization);
        authService.changePassword(
            token,
            request.getNonce(),
            request.getTimestamp(),
            request.getOldHmac(),
            request.getNewPassword()
        );
        return ResponseEntity.ok(Map.of("message", "Mot de passe modifié avec succès. Veuillez vous reconnecter."));
    }

    /**
     * Route protégée — retourne le profil de l'utilisateur authentifié.
     * @param authorization header "Bearer {token}"
     * @return 200 OK avec id, email, createdAt
     */
    @GetMapping("/api/me")
    public ResponseEntity<Map<String, Object>> getMe(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = extractToken(authorization);
        User user = authService.getUserByToken(token);
        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "createdAt", user.getCreatedAt().toString()
        ));
    }

    private String extractToken(String authorization) {
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring(7);
        }
        return authorization;
    }
}
