package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal d'authentification.
 * <p>
 * TP2 : Le mot de passe est désormais haché avec BCrypt avant stockage.
 * Un mécanisme anti brute-force verrouille le compte après 5 échecs pendant 2 minutes.
 * </p>
 * <p>
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
 * </p>
 *
 * @author Tahiry
 * @version 2.0 - TP2
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public static final int MAX_FAILED_ATTEMPTS = 5;
    static final int LOCK_DURATION_MINUTES = 2;

    private final UserRepository userRepository;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository,
                       PasswordPolicyValidator passwordPolicyValidator) {
        this.userRepository = userRepository;
        this.passwordPolicyValidator = passwordPolicyValidator;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    /**
     * Inscrit un nouvel utilisateur avec un mot de passe haché BCrypt.
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair (sera haché avant stockage)
     * @return l'utilisateur créé
     * @throws InvalidInputException     si les données sont invalides ou le mot de passe trop faible
     * @throws ResourceConflictException si l'email existe déjà
     */
    public User register(String email, String password) {
        if (email == null || email.isBlank()) {
            throw new InvalidInputException("L'email ne peut pas être vide");
        }
        if (!email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
            throw new InvalidInputException("Format d'email invalide");
        }

        passwordPolicyValidator.validate(password);

        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription refusée - email déjà existant : {}", email);
            throw new ResourceConflictException("Cet email est déjà utilisé");
        }

        String hashedPassword = passwordEncoder.encode(password);
        User user = new User(email, hashedPassword);
        userRepository.save(user);
        logger.info("Inscription réussie pour : {}", email);
        return user;
    }

    /**
     * Authentifie un utilisateur avec vérification BCrypt et anti brute-force.
     * <p>
     * Après 5 échecs consécutifs, le compte est verrouillé 2 minutes.
     * Le message d'erreur est identique pour un email inconnu ou un mot de passe incorrect
     * afin de ne pas divulguer d'informations.
     * </p>
     *
     * @param email    l'email de l'utilisateur
     * @param password le mot de passe en clair
     * @return le token de session généré
     * @throws InvalidInputException         si les données sont manquantes
     * @throws AccountLockedException        si le compte est temporairement verrouillé
     * @throws AuthenticationFailedException si les identifiants sont incorrects
     */
    public String login(String email, String password) {
        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            throw new InvalidInputException("Email et mot de passe requis");
        }

        User user = userRepository.findByEmail(email).orElse(null);

        // Non-divulgation : même message que le mot de passe incorrect
        if (user == null) {
            logger.warn("Échec connexion - email inconnu : {}", email);
            throw new AuthenticationFailedException("Email ou mot de passe incorrect");
        }

        // Vérification du verrouillage
        if (user.getLockUntil() != null && LocalDateTime.now().isBefore(user.getLockUntil())) {
            logger.warn("Connexion refusée - compte verrouillé : {}", email);
            throw new AccountLockedException("Compte temporairement verrouillé. Réessayez dans 2 minutes.");
        }

        // Vérification BCrypt
        if (!passwordEncoder.matches(password, user.getPassword())) {
            handleFailedAttempt(user);
            logger.warn("Échec connexion - mauvais mot de passe pour : {}", email);
            throw new AuthenticationFailedException("Email ou mot de passe incorrect");
        }

        // Succès : réinitialiser les compteurs
        user.setFailedAttempts(0);
        user.setLockUntil(null);

        String token = UUID.randomUUID().toString();
        user.setSessionToken(token);
        userRepository.save(user);

        logger.info("Connexion réussie pour : {}", email);
        return token;
    }

    /**
     * Incrémente le compteur d'échecs et verrouille le compte si le seuil est atteint.
     *
     * @param user l'utilisateur concerné
     */
    private void handleFailedAttempt(User user) {
        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            user.setLockUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
            logger.warn("Compte verrouillé pour : {}", user.getEmail());
        }
        userRepository.save(user);
    }

    /**
     * Récupère un utilisateur à partir de son token de session.
     *
     * @param token le token de session
     * @return l'utilisateur correspondant
     * @throws AuthenticationFailedException si le token est invalide
     */
    public User getUserByToken(String token) {
        if (token == null || token.isBlank()) {
            throw new AuthenticationFailedException("Token manquant");
        }
        return userRepository.findBySessionToken(token)
                .orElseThrow(() -> new AuthenticationFailedException("Token invalide ou session expirée"));
    }
}
