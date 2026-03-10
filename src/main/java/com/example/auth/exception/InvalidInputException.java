package com.example.auth.exception;

/**
 * Exception levée quand les données d'entrée sont invalides.
 * <p>
 * Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * </p>
 */
public class InvalidInputException extends RuntimeException {
    public InvalidInputException(String message) {
        super(message);
    }
}