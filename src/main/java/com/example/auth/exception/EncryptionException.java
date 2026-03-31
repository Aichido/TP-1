package com.example.auth.exception;

/**
 * Exception levée lors d'un échec de chiffrement ou de déchiffrement AES-GCM (TP4).
 * <p>
 * Peut indiquer :
 * <ul>
 *   <li>Un format de chiffré invalide</li>
 *   <li>Une clé incorrecte</li>
 *   <li>Un chiffré modifié (intégrité GCM compromise)</li>
 * </ul>
 * </p>
 *
 * @author Tahiry
 * @version 4.0 - TP4
 */
public class EncryptionException extends RuntimeException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
