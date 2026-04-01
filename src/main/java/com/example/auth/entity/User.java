package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur en base de données.
 * <p>
 * TP3 : Le mot de passe est stocké de façon réversible (colonne {@code password_encrypted})
 * afin de pouvoir être utilisé comme clé HMAC lors du login sans le transmettre sur le réseau.
 * </p>
 * <p>
 * <b>Avertissement pédagogique :</b> En industrie, on évite de stocker un mot de passe
 * réversible. On préférerait un hash non réversible et adaptatif. Ici, on accepte le
 * chiffrement réversible pour simplifier l'apprentissage du protocole signé.
 * TP4 corrigera ce point avec AES-GCM et une Master Key.
 * </p>
 *
 * @author Tahiry
 * @version 3.0 - TP3
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    /**
     * Mot de passe stocké en clair (TP3).
     * Sera chiffré par AES-GCM avec APP_MASTER_KEY en TP4.
     */
    @Column(name = "password_encrypted", nullable = false)
    private String password;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    /** Token SSO émis après authentification HMAC réussie. */
    @Column(name = "session_token")
    private String sessionToken;

    /** Nombre de tentatives de connexion échouées consécutives. */
    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts = 0;

    /** Date/heure jusqu'à laquelle le compte est verrouillé (null = non verrouillé). */
    @Column(name = "lock_until")
    private LocalDateTime lockUntil;

    public User() {}

    public User(String email, String password) {
        this.email = email;
        this.password = password;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public String getSessionToken() { return sessionToken; }
    public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }

    public LocalDateTime getLockUntil() { return lockUntil; }
    public void setLockUntil(LocalDateTime lockUntil) { this.lockUntil = lockUntil; }
}
