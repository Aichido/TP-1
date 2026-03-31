package com.example.auth.service;

import com.example.auth.exception.InvalidInputException;
import org.springframework.stereotype.Component;

/**
 * Validateur de politique de mot de passe pour TP2.
 * <p>
 * Règles appliquées :
 * <ul>
 *   <li>Minimum 12 caractères</li>
 *   <li>Au moins 1 lettre majuscule</li>
 *   <li>Au moins 1 lettre minuscule</li>
 *   <li>Au moins 1 chiffre</li>
 *   <li>Au moins 1 caractère spécial</li>
 * </ul>
 * </p>
 * <p>
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
 * </p>
 *
 * @author Tahiry
 * @version 2.0 - TP2
 */
@Component
public class PasswordPolicyValidator {

    private static final int MIN_LENGTH = 12;
    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

    /**
     * Valide un mot de passe selon la politique TP2.
     *
     * @param password le mot de passe à valider
     * @throws InvalidInputException si le mot de passe ne respecte pas la politique
     */
    public void validate(String password) {
        if (password == null || password.length() < MIN_LENGTH) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins " + MIN_LENGTH + " caractères");
        }
        if (!password.chars().anyMatch(Character::isUpperCase)) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins une lettre majuscule");
        }
        if (!password.chars().anyMatch(Character::isLowerCase)) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins une lettre minuscule");
        }
        if (!password.chars().anyMatch(Character::isDigit)) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins un chiffre");
        }
        boolean hasSpecial = password.chars()
            .anyMatch(c -> SPECIAL_CHARS.indexOf(c) >= 0);
        if (!hasSpecial) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins un caractère spécial");
        }
    }

    /**
     * Évalue la force d'un mot de passe sur une échelle de 0 à 3.
     *
     * @param password le mot de passe à évaluer
     * @return 0 = non conforme, 1 = faible, 2 = moyen, 3 = fort
     */
    public int strength(String password) {
        if (password == null || password.length() < MIN_LENGTH) {
            return 0;
        }
        try {
            validate(password);
        } catch (InvalidInputException e) {
            return 0;
        }
        int score = 1;
        if (password.length() >= 16) score++;
        if (password.length() >= 20) score++;
        return Math.min(score, 3);
    }
}
