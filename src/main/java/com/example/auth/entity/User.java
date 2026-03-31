package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur en base de données.
 * <p>
 * TP2 : Le mot de passe est désormais stocké sous forme de hash BCrypt
 * (champ {@code password_hash}).
 * Le champ {@code password_clear} du TP1 est supprimé définitivement.
 * </p>
 * <p>
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
 * </p>
 *
 * @author Tahiry
 * @version 2.0 - TP2
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    /** Mot de passe stocké sous forme de hash BCrypt. */
    @Column(name = "password_hash", nullable = false)
    private String password;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    /** Token de session simple pour la route protégée. */
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

    // Getters & Setters
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
