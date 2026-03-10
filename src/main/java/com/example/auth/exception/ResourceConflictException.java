package com.example.auth.exception;

/**
 * Exception levée quand une ressource existe déjà (ex: email doublon).
 * <p>
 * Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * </p>
 */
public class ResourceConflictException extends RuntimeException {
    public ResourceConflictException(String message) {
        super(message);
    }
}