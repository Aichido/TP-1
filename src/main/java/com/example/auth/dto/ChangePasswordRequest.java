package com.example.auth.dto;

/**
 * DTO pour la requête de changement de mot de passe (TP5).
 * <p>
 * L'utilisateur est identifié par son Bearer token (header Authorization).
 * Il prouve la connaissance de l'ancien mot de passe via un HMAC (même protocole que le login).
 * Le nouveau mot de passe est envoyé en clair dans le body HTTPS.
 * </p>
 *
 * Champs :
 * <ul>
 *   <li>{@code nonce} — UUID unique généré par le client (anti-rejeu)</li>
 *   <li>{@code timestamp} — timestamp Unix en secondes (fenêtre ±60 s)</li>
 *   <li>{@code oldHmac} — HMAC-SHA256(ancienMotDePasse, email:nonce:timestamp)</li>
 *   <li>{@code newPassword} — nouveau mot de passe en clair</li>
 * </ul>
 *
 * @author Tahiry
 * @version 5.0 - TP5
 */
public class ChangePasswordRequest {

    private String nonce;
    private long timestamp;
    private String oldHmac;
    private String newPassword;

    public ChangePasswordRequest() {}

    public ChangePasswordRequest(String nonce, long timestamp, String oldHmac, String newPassword) {
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.oldHmac = oldHmac;
        this.newPassword = newPassword;
    }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getOldHmac() { return oldHmac; }
    public void setOldHmac(String oldHmac) { this.oldHmac = oldHmac; }

    public String getNewPassword() { return newPassword; }
    public void setNewPassword(String newPassword) { this.newPassword = newPassword; }
}
