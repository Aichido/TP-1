package com.example.auth.controller;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.LoginResponse;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Contrôleur REST pour l'authentification.
 * <p>
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * </p>
 * Endpoints :
 * - POST /api/auth/register  : inscription
 * - POST /api/auth/login     : connexion
 * - GET  /api/me             : profil (route protégée)
 *
 * @author Tahiry
 * @version 1.0 - TP1
 */
@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Endpoint d'inscription.
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
     * Endpoint de connexion.
     * @param request corps JSON avec email et password
     * @return 200 OK avec token si succès
     */
    @PostMapping("/api/auth/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        String token = authService.login(request.getEmail(), request.getPassword());
        return ResponseEntity.ok(new LoginResponse(token, "Connexion réussie"));
    }

    /**
     * Route protégée - accessible uniquement avec un token valide.
     * @param authorization header "Bearer {token}"
     * @return les informations de l'utilisateur authentifié
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