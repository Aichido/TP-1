package com.example.auth.exception;

/**
 * Exception levée lorsqu'un compte est temporairement verrouillé
 * suite à trop de tentatives de connexion échouées.
 * <p>
 * Correspond au code HTTP 423 (Locked).
 * </p>
 *
 * @author Tahiry
 * @version 2.0 - TP2
 */
public class AccountLockedException extends RuntimeException {

    public AccountLockedException(String message) {
        super(message);
    }
}
