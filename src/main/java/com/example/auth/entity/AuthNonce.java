package com.example.auth.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entité représentant un nonce d'authentification pour la protection anti-rejeu.
 * <p>
 * Chaque nonce est lié à un utilisateur et possède une date d'expiration.
 * Un nonce consommé ne peut plus être réutilisé, ce qui empêche les attaques par rejeu.
 * </p>
 * <p>
 * Contrainte unique : {@code (user_id, nonce)} pour garantir l'unicité par utilisateur.
 * </p>
 *
 * @author Tahiry
 * @version 3.0 - TP3
 */
@Entity
@Table(name = "auth_nonce",
    uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "nonce"}))
public class AuthNonce {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Utilisateur auquel ce nonce appartient. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** Valeur UUID du nonce, unique par utilisateur. */
    @Column(nullable = false)
    private String nonce;

    /** Date/heure d'expiration du nonce (now + 2 minutes). */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /** Indique si le nonce a déjà été utilisé pour une authentification. */
    @Column(nullable = false)
    private boolean consumed = false;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    public AuthNonce() {}

    public AuthNonce(User user, String nonce, LocalDateTime expiresAt) {
        this.user = user;
        this.nonce = nonce;
        this.expiresAt = expiresAt;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() { return id; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }

    public boolean isConsumed() { return consumed; }
    public void setConsumed(boolean consumed) { this.consumed = consumed; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
