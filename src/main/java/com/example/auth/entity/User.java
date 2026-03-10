package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un utilisateur en base de données.
 * <p>
 * NB : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * Le mot de passe est stocké en clair, ce qui constitue une faille
 * de sécurité critique.
 * </p>
 *
 * @author Tahiry
 * @version 1.0 - TP1
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
     * Mot de passe stocké en CLAIR.
     */
    @Column(name = "password_clear", nullable = false)
    private String password;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    // Token simple pour la route protégée
    @Column(name = "session_token")
    private String sessionToken;

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
}