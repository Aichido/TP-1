package com.example.auth;

import com.example.auth.repository.UserRepository;
import com.example.auth.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Initialise le compte de test obligatoire au démarrage de l'application.
 * <p>
 * Exécuté uniquement hors profil {@code test} (pas en CI ni en tests JUnit).<br>
 * Le mot de passe est chiffré via AES-GCM avant stockage, conformément à TP4.
 * </p>
 * <p>
 * Compte créé : {@code toto@example.com / Toto1234!@secure}
 * </p>
 *
 * @author Tahiry
 * @version 4.0 - TP4
 */
@Component
@Profile("!test")
public class DataInitializer implements ApplicationRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    private final UserRepository userRepository;
    private final AuthService authService;

    public DataInitializer(UserRepository userRepository, AuthService authService) {
        this.userRepository = userRepository;
        this.authService = authService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.findByEmail("toto@example.com").isEmpty()) {
            try {
                authService.register("toto@example.com", "Toto1234!@secure");
                logger.info("Compte de test créé avec mot de passe chiffré AES-GCM : toto@example.com");
            } catch (Exception e) {
                logger.warn("Impossible de créer le compte de test : {}", e.getMessage());
            }
        } else {
            logger.debug("Compte de test déjà existant : toto@example.com");
        }
    }
}
