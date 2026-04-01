package com.example.auth.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Service de calcul et vérification HMAC-SHA256 pour le protocole d'authentification TP3.
 * <p>
 * Le HMAC (Hash-based Message Authentication Code) permet au client de prouver
 * qu'il connaît le mot de passe sans jamais le transmettre sur le réseau.
 * </p>
 * <p>
 * Protocole : {@code hmac = HMAC_SHA256(key = password, data = email + ":" + nonce + ":" + timestamp)}
 * </p>
 * <p>
 * <b>Limite pédagogique :</b> Ce mécanisme suppose que le serveur dispose du mot de passe
 * en clair pour recalculer le HMAC. En industrie, on préférerait un protocole basé sur
 * une clé dérivée (PBKDF2, Argon2) ou un protocole SRP.
 * </p>
 *
 * @author Tahiry
 * @version 3.0 - TP3
 */
@Service
public class HmacService {

    private static final String HMAC_ALGO = "HmacSHA256";

    /**
     * Calcule la signature HMAC-SHA256 d'un message avec une clé donnée.
     *
     * @param key     la clé secrète (mot de passe en clair)
     * @param message le message à signer ({@code email:nonce:timestamp})
     * @return la signature encodée en Base64
     * @throws HmacComputationException si le calcul échoue
     */
    public String compute(String key, String message) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), HMAC_ALGO);
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(keySpec);
            byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new HmacComputationException("Erreur lors du calcul HMAC", e);
        }
    }

    /**
     * Compare deux signatures HMAC en temps constant pour éviter les attaques par timing.
     * <p>
     * Une comparaison naïve ({@code a.equals(b)}) s'arrête au premier caractère différent,
     * révélant des informations par le temps de réponse. {@link MessageDigest#isEqual}
     * garantit un temps constant quelle que soit la différence.
     * </p>
     *
     * @param expected la signature attendue calculée côté serveur
     * @param received la signature reçue du client
     * @return {@code true} si les signatures sont identiques
     */
    public boolean compareConstantTime(String expected, String received) {
        if (expected == null || received == null) {
            return false;
        }
        return MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            received.getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Construit le message à signer.
     *
     * @param email     l'email de l'utilisateur
     * @param nonce     le nonce UUID
     * @param timestamp le timestamp Unix en secondes
     * @return le message formaté {@code email:nonce:timestamp}
     */
    public String buildMessage(String email, String nonce, long timestamp) {
        return email + ":" + nonce + ":" + timestamp;
    }

    /** Exception interne pour les erreurs de calcul HMAC. */
    public static class HmacComputationException extends RuntimeException {
        public HmacComputationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
