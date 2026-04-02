# TP2 — Sécurité du mot de passe : politique, hachage et protection anti-bruteforce

## Vue d'ensemble

Avant ce TP, l'application stockait les mots de passe **en clair** dans la base de données. Si un attaquant accédait à la base, il obtenait immédiatement tous les mots de passe. TP2 corrige trois problèmes fondamentaux :

1. Les mots de passe sont trop faibles (pas de règles)
2. Les mots de passe sont stockés en clair (lisibles directement)
3. Un attaquant peut tenter des milliers de mots de passe sans limite (bruteforce)

---

## Étape 1 — Politique de mot de passe

### Pourquoi ?

Un mot de passe comme `123456` ou `password` est devinable en quelques secondes par un attaquant qui utilise des listes de mots de passe courants. Il faut imposer des règles minimales de complexité.

### Ce qu'on a fait

On a créé un composant Spring `PasswordPolicyValidator` qui valide chaque mot de passe avant inscription :

```java
// src/main/java/com/example/auth/service/PasswordPolicyValidator.java

@Component
public class PasswordPolicyValidator {

    private static final int MIN_LENGTH = 12;
    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

    public void validate(String password) {
        // Longueur minimale
        if (password == null || password.length() < MIN_LENGTH) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins " + MIN_LENGTH + " caractères");
        }
        // Au moins une majuscule
        if (!password.chars().anyMatch(Character::isUpperCase)) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins une lettre majuscule");
        }
        // Au moins une minuscule
        if (!password.chars().anyMatch(Character::isLowerCase)) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins une lettre minuscule");
        }
        // Au moins un chiffre
        if (!password.chars().anyMatch(Character::isDigit)) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins un chiffre");
        }
        // Au moins un caractère spécial
        boolean hasSpecial = password.chars()
            .anyMatch(c -> SPECIAL_CHARS.indexOf(c) >= 0);
        if (!hasSpecial) {
            throw new InvalidInputException(
                "Le mot de passe doit contenir au moins un caractère spécial");
        }
    }
}
```

**Points clés à comprendre :**

- `password.chars()` retourne un `IntStream` représentant chaque caractère Unicode du mot de passe.
- `anyMatch(Character::isUpperCase)` vérifie si au moins un caractère est une majuscule.
- On lève une `InvalidInputException` (exception métier personnalisée) qui sera traduite en HTTP 400 par le `GlobalExceptionHandler`.

### La méthode `strength()`

En bonus, on a ajouté une méthode pour évaluer la "force" du mot de passe sur une échelle 0-3 :

```java
public int strength(String password) {
    if (password == null || password.length() < MIN_LENGTH) {
        return 0; // non conforme
    }
    try {
        validate(password);
    } catch (InvalidInputException e) {
        return 0;
    }
    int score = 1; // conforme = score de base
    if (password.length() >= 16) score++; // bonus longueur
    if (password.length() >= 20) score++; // bonus longueur ++
    return Math.min(score, 3);
}
```

---

## Étape 2 — Hachage BCrypt (plus de mots de passe en clair)

### Pourquoi le hachage ?

Stocker `monMotDePasse` en clair est catastrophique. Si la base fuite, tout le monde est compromis.

On pourrait chiffrer les mots de passe, mais alors on aurait besoin d'une clé de déchiffrement — et si cette clé est volée, même combat.

La solution : le **hachage**. Un hash est **non réversible** (on ne peut pas retrouver le mot de passe depuis le hash). Pour vérifier un mot de passe au login, on le hache à nouveau et on compare les deux hashs.

**Pourquoi BCrypt spécifiquement ?**

BCrypt est un algorithme de hachage **adaptatif** et **lent** par design. Il intègre un "facteur de coût" qui permet d'augmenter le temps de calcul au fil des années, sans casser la compatibilité. Il intègre également un **sel** (salt) aléatoire par défaut, ce qui empêche les attaques par tables arc-en-ciel (rainbow tables).

### Ce qu'on a fait dans `AuthService`

```java
// À l'inscription
String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
User user = new User(email, hashedPassword);
userRepository.save(user);

// Au login
User user = userRepository.findByEmail(email).orElseThrow(...);
if (!BCrypt.checkpw(passwordCandidat, user.getPassword())) {
    // mot de passe incorrect
    handleFailedAttempt(user);
    throw new AuthenticationFailedException("Authentification échouée");
}
```

**Points clés :**
- `BCrypt.gensalt()` génère un sel aléatoire unique pour chaque utilisateur.
- `BCrypt.hashpw(password, salt)` produit quelque chose comme `$2a$10$...` (le résultat inclut l'algorithme, le coût et le sel).
- `BCrypt.checkpw(candidat, hash)` refait le hachage avec le même sel (extrait du hash stocké) et compare.

### Évolution du schéma de la base de données

On a renommé la colonne `password_clear` en `password_hash` pour refléter que le mot de passe est maintenant haché :

```sql
-- Avant (TP1)
ALTER TABLE users ADD COLUMN password_clear VARCHAR(255);

-- Après (TP2)
ALTER TABLE users ADD COLUMN password_hash VARCHAR(255);
```

---

## Étape 3 — Protection anti-bruteforce

### L'attaque bruteforce

Un attaquant peut écrire un script qui teste des milliers de mots de passe sur le formulaire de login. Même avec BCrypt (lent), avec un botnet puissant, c'est faisable.

La défense classique : **verrouiller le compte temporairement** après N échecs consécutifs.

### Ce qu'on a fait dans l'entité `User`

On a ajouté deux colonnes à la table `users` :

```java
// src/main/java/com/example/auth/entity/User.java

/** Nombre de tentatives de connexion échouées consécutives. */
@Column(name = "failed_attempts", nullable = false)
private int failedAttempts = 0;

/** Date/heure jusqu'à laquelle le compte est verrouillé (null = non verrouillé). */
@Column(name = "lock_until")
private LocalDateTime lockUntil;
```

### La logique de verrouillage dans `AuthService`

```java
// src/main/java/com/example/auth/service/AuthService.java

public static final int MAX_FAILED_ATTEMPTS = 5;
static final int LOCK_DURATION_MINUTES = 2;

// Appelé à chaque échec de login
private void handleFailedAttempt(User user) {
    int attempts = user.getFailedAttempts() + 1;
    user.setFailedAttempts(attempts);
    if (attempts >= MAX_FAILED_ATTEMPTS) {
        user.setLockUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
        logger.warn("Compte verrouillé pour : {}", user.getEmail());
    }
    userRepository.save(user);
}
```

### Vérification du verrouillage au début du login

```java
// Au début de la méthode login()
if (user.getLockUntil() != null && LocalDateTime.now().isBefore(user.getLockUntil())) {
    logger.warn("Login refusé - compte verrouillé : {}", email);
    throw new AccountLockedException("Compte temporairement verrouillé. Réessayez dans 2 minutes.");
}
```

Le `GlobalExceptionHandler` traduit `AccountLockedException` en **HTTP 423 (Locked)**.

### Réinitialisation au succès

Après un login réussi, on remet le compteur à zéro :

```java
user.setFailedAttempts(0);
user.setLockUntil(null);
userRepository.save(user);
```

---

## Récapitulatif : ce que TP2 a apporté

| Problème initial | Solution TP2 |
|---|---|
| Mot de passe trop faible | `PasswordPolicyValidator` : 12 car., maj., min., chiffre, spécial |
| Mot de passe en clair en BDD | Hachage BCrypt (non réversible, avec sel) |
| Bruteforce illimité | Verrouillage 2 min après 5 échecs |

## Ce qui reste à améliorer (TP3 et TP4)

- Le mot de passe **transite encore en clair** sur le réseau au moment du login (HTTP POST).
- Si un attaquant intercepte la requête (homme-du-milieu), il récupère le mot de passe.
- TP3 résoudra cela avec le protocole HMAC.

---

## Tests associés

Les tests dans `AuthServiceTest.java` couvrent notamment :

```java
// Inscription valide
@Test
void registerShouldSucceedWithValidData() {
    assertDoesNotThrow(() -> authService.register(VALID_EMAIL, VALID_PASSWORD));
}

// Mot de passe trop court → rejeté
@Test
void registerShouldFailWhenPasswordTooShort() {
    assertThrows(InvalidInputException.class,
        () -> authService.register(VALID_EMAIL, "Short1!"));
}

// Verrouillage après 5 échecs
@Test
void loginShouldLockAccountAfterFiveFailedAttempts() {
    authService.register(VALID_EMAIL, VALID_PASSWORD);

    for (int i = 0; i < AuthService.MAX_FAILED_ATTEMPTS; i++) {
        try {
            authService.login(VALID_EMAIL, "bad_password");
        } catch (AuthenticationFailedException ignored) {}
    }

    // Le 6ème essai, même avec le bon mot de passe, est refusé
    assertThrows(AccountLockedException.class,
        () -> authService.login(VALID_EMAIL, VALID_PASSWORD));
}
```
