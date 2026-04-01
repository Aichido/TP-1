package com.example.auth.repository;

import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository JPA pour la gestion des nonces d'authentification.
 */
public interface AuthNonceRepository extends JpaRepository<AuthNonce, Long> {

    /** Recherche un nonce par utilisateur et valeur (pour détecter le rejeu). */
    Optional<AuthNonce> findByUserAndNonce(User user, String nonce);

    /** Supprime les nonces expirés (nettoyage périodique). */
    @Modifying
    @Query("DELETE FROM AuthNonce n WHERE n.expiresAt < :now")
    void deleteExpiredNonces(LocalDateTime now);
}
