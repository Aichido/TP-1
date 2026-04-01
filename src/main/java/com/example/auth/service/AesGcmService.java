package com.example.auth.service;

import com.example.auth.exception.EncryptionException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement AES-256-GCM pour la protection des mots de passe au repos (TP4).
 * <p>
 * La <b>Server Master Key (SMK)</b> est injectée via la variable d'environnement
 * {@code APP_MASTER_KEY}. Elle ne doit jamais être codée en dur dans le code source
 * ni apparaître dans les logs.
 * </p>
 * <p>
 * <b>Format de stockage :</b> {@code v1:Base64(iv):Base64(ciphertext)}<br>
 * Un IV de 96 bits est généré aléatoirement à chaque chiffrement, garantissant
 * la sécurité sémantique : un même mot de passe donne toujours un chiffré différent.
 * </p>
 * <p>
 * AES-GCM (Galois/Counter Mode) est un algorithme AEAD : il fournit simultanément
 * confidentialité et intégrité. Toute modification du chiffré est détectée au
 * déchiffrement (tag d'authentification de 128 bits).
 * </p>
 * <p>
 * <b>Interdictions strictes :</b>
 * <ul>
 *   <li>Pas de clé codée en dur</li>
 *   <li>Pas d'IV fixe (chaque chiffrement génère un IV aléatoire)</li>
 *   <li>Pas de mode ECB</li>
 *   <li>Pas de log du mot de passe</li>
 * </ul>
 * </p>
 *
 * @author Tahiry
 * @version 4.0 - TP4
 */
@Service
public class AesGcmService {

    private static final String ALGO = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;   // 96 bits – recommandé par NIST SP 800-38D
    private static final int GCM_TAG_BITS  = 128;  // tag d'authentification 128 bits

    private final SecretKeySpec masterKey;

    /**
     * Construit le service avec la Master Key injectée par Spring.
     * L'application refuse de démarrer si la clé est absente ou vide.
     *
     * @param rawKey la valeur de {@code APP_MASTER_KEY} (jamais en dur dans le code)
     * @throws IllegalStateException si la clé est absente ou vide
     */
    public AesGcmService(@Value("${app.master-key}") String rawKey) {
        if (rawKey == null || rawKey.isBlank()) {
            throw new IllegalStateException(
                "APP_MASTER_KEY est obligatoire. L'application ne peut pas démarrer sans clé maître.");
        }
        this.masterKey = new SecretKeySpec(deriveKey256(rawKey), "AES");
    }

    /**
     * Chiffre un texte en clair avec AES-256-GCM.
     * Un IV aléatoire est généré à chaque appel.
     *
     * @param plaintext le texte à chiffrer (mot de passe en clair)
     * @return la chaîne chiffrée au format {@code v1:Base64(iv):Base64(ciphertext)}
     * @throws EncryptionException si le chiffrement échoue
     */
    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return "v1:"
                + Base64.getEncoder().encodeToString(iv) + ":"
                + Base64.getEncoder().encodeToString(ciphertext);
        } catch (Exception e) {
            throw new EncryptionException("Échec du chiffrement AES-GCM", e);
        }
    }

    /**
     * Déchiffre une valeur au format {@code v1:Base64(iv):Base64(ciphertext)}.
     * L'intégrité du chiffré est vérifiée par le tag GCM.
     *
     * @param encrypted la chaîne chiffrée
     * @return le texte en clair
     * @throws EncryptionException si le format est invalide, la clé incorrecte
     *                             ou le chiffré a été modifié
     */
    public String decrypt(String encrypted) {
        if (encrypted == null || !encrypted.startsWith("v1:")) {
            throw new EncryptionException("Format chiffré invalide ou version non supportée");
        }
        try {
            String[] parts = encrypted.split(":", 3);
            if (parts.length != 3) {
                throw new EncryptionException("Format chiffré invalide : attendu v1:iv:ciphertext");
            }
            byte[] iv         = Base64.getDecoder().decode(parts[1]);
            byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new EncryptionException("Intégrité du chiffré compromise (tag invalide)", e);
        } catch (EncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionException("Échec du déchiffrement AES-GCM", e);
        }
    }

    /**
     * Dérive une clé AES-256 (32 octets) à partir d'une chaîne arbitraire via SHA-256.
     * Cette dérivation garantit que la clé fait exactement 256 bits quelle que soit
     * la longueur de la Master Key fournie.
     */
    private byte[] deriveKey256(String rawKey) {
        try {
            return MessageDigest.getInstance("SHA-256")
                .digest(rawKey.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Impossible de dériver la clé AES-256", e);
        }
    }
}
