package com.example.auth.exception;

/**
 * Exception levée quand l'authentification échoue.
 * <p>
 * Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * </p>
 */
public class AuthenticationFailedException extends RuntimeException {
    public AuthenticationFailedException(String message) {
        super(message);
    }
}