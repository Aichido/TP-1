package com.example.auth.service;

import com.example.auth.entity.AuthNonce;
import com.example.auth.entity.User;
import com.example.auth.exception.AccountLockedException;
import com.example.auth.exception.AuthenticationFailedException;
import com.example.auth.exception.InvalidInputException;
import com.example.auth.exception.ResourceConflictException;
import com.example.auth.repository.AuthNonceRepository;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal d'authentification.
 * <p>
 * TP3 : Le protocole de login passe de "envoi du mot de passe" à "preuve HMAC".
 * Le client calcule {@code HMAC_SHA256(key=password, data=email+":"+nonce+":"+timestamp)}
 * et envoie cette preuve sans jamais transmettre le mot de passe.
 * Le serveur recalcule le HMAC côté serveur et compare en temps constant.
 * </p>
 * <p>
 * <b>Limite pédagogique :</b> Le mot de passe est stocké en clair ({@code password_encrypted})
 * pour permettre le recalcul HMAC. Ce stockage réversible sera chiffré en TP4 avec AES-GCM.
 * TP3 améliore le protocole de transit mais ne protège pas encore le stockage au repos.
 * </p>
 *
 * @author Tahiry
 * @version 3.0 - TP3
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    public static final int MAX_FAILED_ATTEMPTS = 5;
    static final int LOCK_DURATION_MINUTES = 2;
    static final long TIMESTAMP_WINDOW_SECONDS = 60L;
    static final long NONCE_TTL_SECONDS = 120L;
    static final long TOKEN_TTL_MINUTES = 15L;

    private final UserRepository userRepository;
    private final AuthNonceRepository authNonceRepository;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final HmacService hmacService;

    public AuthService(UserRepository userRepository,
                       AuthNonceRepository authNonceRepository,
                       PasswordPolicyValidator passwordPolicyValidator,
                       HmacService hmacService) {
        this.userRepository = userRepository;
        this.authNonceRepository = authNonceRepository;
        this.passwordPolicyValidator = passwordPolicyValidator;
        this.hmacService = hmacService;
    }

    /**
     * Inscrit un nouvel utilisateur.
     * Le mot de passe est stocké en clair (TP3 pédagogique) pour servir de clé HMAC.
     *
     * @param email    l'adresse email de l'utilisateur
     * @param password le mot de passe en clair (sera chiffré AES-GCM en TP4)
     * @return l'utilisateur créé
     * @throws InvalidInputException     si les données sont invalides
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

        // TP3 : stockage en clair (sera chiffré AES-GCM en TP4)
        User user = new User(email, password);
        userRepository.save(user);
        logger.info("Inscription réussie pour : {}", email);
        return user;
    }

    /**
     * Authentifie un utilisateur via le protocole HMAC avec protection anti-rejeu.
     * <p>
     * Vérifications dans l'ordre :
     * <ol>
     *   <li>Email connu (sinon 401 — message générique)</li>
     *   <li>Compte non verrouillé (sinon 423)</li>
     *   <li>Timestamp dans la fenêtre ±60 s (sinon 401)</li>
     *   <li>Nonce non déjà utilisé (sinon 401)</li>
     *   <li>HMAC valide, comparé en temps constant (sinon 401)</li>
     * </ol>
     * </p>
     *
     * @param email     l'email de l'utilisateur
     * @param nonce     le nonce UUID unique généré par le client
     * @param timestamp le timestamp Unix en secondes
     * @param hmac      la signature HMAC-SHA256 encodée en Base64
     * @return le token SSO émis (valide 15 minutes)
     * @throws InvalidInputException         si des champs sont manquants
     * @throws AccountLockedException        si le compte est verrouillé
     * @throws AuthenticationFailedException si la vérification échoue
     */
    public String login(String email, String nonce, long timestamp, String hmac) {
        if (email == null || email.isBlank() || nonce == null || nonce.isBlank()
                || hmac == null || hmac.isBlank()) {
            throw new InvalidInputException("email, nonce et hmac sont obligatoires");
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            logger.warn("Échec login HMAC - email inconnu : {}", email);
            throw new AuthenticationFailedException("Authentification échouée");
        }

        if (user.getLockUntil() != null && LocalDateTime.now().isBefore(user.getLockUntil())) {
            logger.warn("Login refusé - compte verrouillé : {}", email);
            throw new AccountLockedException("Compte temporairement verrouillé. Réessayez dans 2 minutes.");
        }

        // Vérification timestamp ±60 secondes
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW_SECONDS) {
            logger.warn("Login refusé - timestamp invalide pour : {}", email);
            throw new AuthenticationFailedException("Authentification échouée");
        }

        // Vérification anti-rejeu : nonce déjà vu ?
        if (authNonceRepository.findByUserAndNonce(user, nonce).isPresent()) {
            logger.warn("Login refusé - nonce déjà utilisé pour : {}", email);
            throw new AuthenticationFailedException("Authentification échouée");
        }

        // Enregistrement du nonce (consommé immédiatement)
        AuthNonce authNonce = new AuthNonce(user, nonce,
            LocalDateTime.now().plusSeconds(NONCE_TTL_SECONDS));
        authNonce.setConsumed(true);
        authNonceRepository.save(authNonce);

        // Recalcul HMAC côté serveur
        String message = hmacService.buildMessage(email, nonce, timestamp);
        String expectedHmac = hmacService.compute(user.getPassword(), message);

        // Comparaison en temps constant
        if (!hmacService.compareConstantTime(expectedHmac, hmac)) {
            handleFailedAttempt(user);
            logger.warn("Échec login HMAC - signature invalide pour : {}", email);
            throw new AuthenticationFailedException("Authentification échouée");
        }

        // Succès : réinitialiser compteurs et émettre token SSO
        user.setFailedAttempts(0);
        user.setLockUntil(null);
        String token = UUID.randomUUID().toString();
        user.setSessionToken(token);
        userRepository.save(user);

        logger.info("Connexion HMAC réussie pour : {}", email);
        return token;
    }

    /**
     * Récupère un utilisateur à partir de son token SSO.
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
                .orElseThrow(() -> new AuthenticationFailedException("Token invalide ou expiré"));
    }

    private void handleFailedAttempt(User user) {
        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            user.setLockUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
            logger.warn("Compte verrouillé pour : {}", user.getEmail());
        }
        userRepository.save(user);
    }
}
