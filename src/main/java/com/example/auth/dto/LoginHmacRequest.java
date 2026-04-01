package com.example.auth.dto;

/**
 * DTO pour la requête de login HMAC (TP3).
 * <p>
 * Le client envoie une preuve cryptographique de connaissance du mot de passe
 * sans jamais transmettre le mot de passe lui-même.
 * </p>
 * <p>
 * Protocole : {@code hmac = HMAC_SHA256(key=password, data=email+":"+nonce+":"+timestamp)}
 * </p>
 */
public class LoginHmacRequest {

    private String email;
    /** UUID aléatoire généré par le client pour chaque requête. */
    private String nonce;
    /** Timestamp Unix en secondes au moment de la requête. */
    private long timestamp;
    /** Signature HMAC-SHA256 encodée en Base64. */
    private String hmac;

    public LoginHmacRequest() {}

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public String getHmac() { return hmac; }
    public void setHmac(String hmac) { this.hmac = hmac; }
}
