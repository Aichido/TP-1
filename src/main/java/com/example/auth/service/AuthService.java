package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Service principal d'authentification.
 * <p>
 * AVERTISSEMENT : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * Les mots de passe sont stockés et comparés en clair.
 * </p>
 *
 * @author Tahiry
 * @version 1.0 - TP1
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Inscrit un nouvel utilisateur.
     * Validation minimale : email non vide, format basique, mot de passe >= 4 caractères.
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair (volontairement stocké tel quel)
     * @return l'utilisateur créé
     * @throws InvalidInputException      si les données sont invalides
     * @throws ResourceConflictException  si l'email existe déjà
     */
    public User register(String email, String password) {
        // Validation email
        if (email == null || email.isBlank()) {
            throw new InvalidInputException("L'email ne peut pas être vide");
        }
        if (!email.contains("@") || !email.contains(".")) {
            throw new InvalidInputException("Format d'email invalide");
        }

        // Validation mot de passe (volontairement faible - TP1)
        if (password == null || password.length() < 4) {
            throw new InvalidInputException("Le mot de passe doit faire au moins 4 caractères");
        }

        // Vérifier si l'email est unique
        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Tentative d'inscription avec email déjà existant : {}", email);
            throw new ResourceConflictException("Cet email est déjà utilisé");
        }

        User user = new User(email, password);
        userRepository.save(user);
        logger.info("Inscription réussie pour : {}", email);
        return user;
    }

    /**
     * Authentifie un utilisateur et génère un token de session.
     * Comparaison du mot de passe en clair - volontairement non sécurisé.
     *
     * @param email    l'email de l'utilisateur
     * @param password le mot de passe en clair
     * @return le token de session généré
     * @throws InvalidInputException         si les données sont manquantes
     * @throws AuthenticationFailedException si les identifiants sont incorrects
     */
    public String login(String email, String password) {
        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            throw new InvalidInputException("Email et mot de passe requis");
        }

        User user = userRepository.findByEmail(email).orElse(null);

        // Comparaison directe en clair - DANGEREUX
        if (user == null || !user.getPassword().equals(password)) {
            logger.warn("Échec connexion pour email : {}", email);
            throw new AuthenticationFailedException("Email ou mot de passe incorrect");
        }

        // Génération d'un token basique
        String token = UUID.randomUUID().toString();
        user.setSessionToken(token);
        userRepository.save(user);

        logger.info("Connexion réussie pour : {}", email);
        return token;
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