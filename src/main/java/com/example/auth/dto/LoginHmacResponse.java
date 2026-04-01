package com.example.auth.dto;

/**
 * DTO pour la réponse de login HMAC réussi (TP3).
 * Contient le token SSO et sa date d'expiration.
 */
public class LoginHmacResponse {

    private String accessToken;
    private String expiresAt;
    private String message;

    public LoginHmacResponse(String accessToken, String expiresAt, String message) {
        this.accessToken = accessToken;
        this.expiresAt = expiresAt;
        this.message = message;
    }

    public String getAccessToken() { return accessToken; }
    public String getExpiresAt() { return expiresAt; }
    public String getMessage() { return message; }
}
