# TP3 — Protocole HMAC et protection anti-rejeu

## Le problème que TP3 résout

Après TP2, les mots de passe sont bien hachés en base de données. Mais lors du login, le client envoie encore le mot de passe **en clair** dans la requête HTTP :

```json
POST /api/auth/login
{
  "email": "alice@example.com",
  "password": "MonMotDePasse1!xy"
}
```

Un attaquant qui intercepte ce trafic (attaque "homme-du-milieu") récupère directement le mot de passe. En plus, si l'attaquant enregistre la requête, il peut la **rejouer** plus tard pour se connecter à nouveau — même s'il ne connaît pas le mot de passe.

TP3 introduit un protocole cryptographique qui résout ces deux problèmes :
- Le mot de passe **ne transite jamais** sur le réseau.
- Chaque requête de login est **unique et non rejouable**.

---

## Comprendre le HMAC

### C'est quoi un MAC ?

Un **MAC** (Message Authentication Code) est une empreinte cryptographique d'un message, calculée avec une **clé secrète**. Il prouve que l'émetteur connaît la clé sans la révéler.

Un **HMAC** (Hash-based MAC) utilise une fonction de hachage (ici SHA-256) en interne.

### L'idée du protocole

Au lieu d'envoyer son mot de passe, le client prouve qu'il le connaît en calculant :

```
hmac = HMAC_SHA256(clé = mot_de_passe, données = email + ":" + nonce + ":" + timestamp)
```

Le serveur, qui connaît aussi le mot de passe (stocké en base), refait le même calcul et compare. Si les deux valeurs correspondent, l'identité est prouvée.

---

## Étape 1 — Le `HmacService`

```java
// src/main/java/com/example/auth/service/HmacService.java

@Service
public class HmacService {

    private static final String HMAC_ALGO = "HmacSHA256";

    /**
     * Calcule HMAC-SHA256(key, message) et retourne le résultat en Base64.
     */
    public String compute(String key, String message) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), HMAC_ALGO);
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(keySpec);
            byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new HmacComputationException("Erreur lors du calcul HMAC", e);
        }
    }

    /**
     * Construit le message à signer : "email:nonce:timestamp"
     */
    public String buildMessage(String email, String nonce, long timestamp) {
        return email + ":" + nonce + ":" + timestamp;
    }
}
```

**Comment ça fonctionne techniquement :**

1. `SecretKeySpec` encapsule la clé (le mot de passe en bytes UTF-8) pour l'algorithme HMAC-SHA256.
2. `Mac.getInstance("HmacSHA256")` obtient l'implémentation de l'algorithme depuis le JCA (Java Cryptography Architecture).
3. `mac.doFinal(message)` calcule l'empreinte HMAC du message.
4. `Base64.getEncoder().encodeToString(hash)` encode le résultat binaire (32 octets) en une chaîne lisible.

---

## Étape 2 — La comparaison en temps constant

### Le problème de la comparaison naïve

```java
// DANGEREUX - ne jamais faire ça
if (expected.equals(received)) { ... }
```

La méthode `equals()` de Java s'arrête **au premier caractère différent**. Un attaquant sophistiqué peut mesurer le temps de réponse du serveur et déduire combien de caractères de son HMAC forgé correspondent au HMAC attendu. C'est une **attaque par canal auxiliaire temporel** (timing attack).

### La solution : `MessageDigest.isEqual()`

```java
public boolean compareConstantTime(String expected, String received) {
    if (expected == null || received == null) {
        return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8),
        received.getBytes(StandardCharsets.UTF_8)
    );
}
```

`MessageDigest.isEqual()` compare **toujours tous les octets**, même si les premiers sont différents. Le temps de réponse est donc identique quel que soit l'écart entre les deux valeurs.

---

## Étape 3 — La protection anti-rejeu avec nonce + timestamp

### Le nonce

Un **nonce** (Number used ONCE) est un identifiant unique généré par le client pour chaque requête. Le serveur mémorise les nonces utilisés et rejette toute requête qui en présente un déjà vu.

### Le timestamp

Le timestamp (heure Unix en secondes) sert à limiter la fenêtre de validité d'une requête. Le serveur refuse les requêtes dont le timestamp est en dehors de ±60 secondes.

### L'entité `AuthNonce`

```java
// src/main/java/com/example/auth/entity/AuthNonce.java

@Entity
@Table(name = "auth_nonce",
    uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "nonce"}))
public class AuthNonce {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String nonce;           // UUID envoyé par le client

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt; // now + 120 secondes

    @Column(nullable = false)
    private boolean consumed = false; // true dès qu'il est utilisé
}
```

**Points importants :**
- La contrainte `@UniqueConstraint(columnNames = {"user_id", "nonce"})` garantit au niveau base de données qu'un même nonce ne peut pas être inséré deux fois pour le même utilisateur.
- Le champ `consumed` est mis à `true` immédiatement lors de la première utilisation.

---

## Étape 4 — La requête et réponse de login (DTOs)

### Ce que le client envoie

```java
// src/main/java/com/example/auth/dto/LoginHmacRequest.java

public class LoginHmacRequest {
    private String email;
    private String nonce;     // UUID aléatoire généré par le client
    private long timestamp;   // timestamp Unix en secondes
    private String hmac;      // HMAC-SHA256 encodé en Base64
}
```

Exemple de requête JSON :

```json
POST /api/auth/login
{
  "email": "alice@example.com",
  "nonce": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "timestamp": 1711234567,
  "hmac": "dGhpcyBpcyBhIGZha2UgaG1hYyBmb3IgZXhhbXBsZQ=="
}
```

### Ce que le serveur retourne

```java
// src/main/java/com/example/auth/dto/LoginHmacResponse.java

public class LoginHmacResponse {
    private String accessToken; // UUID token SSO
    private String expiresAt;   // ISO-8601 : maintenant + 15 minutes
    private String message;
}
```

---

## Étape 5 — Le flux complet dans `AuthService.login()`

Voici la logique de vérification dans l'ordre, avec les défenses correspondantes :

```java
// src/main/java/com/example/auth/service/AuthService.java

public String login(String email, String nonce, long timestamp, String hmac) {

    // 1. L'utilisateur existe-t-il ?
    User user = userRepository.findByEmail(email).orElse(null);
    if (user == null) {
        throw new AuthenticationFailedException("Authentification échouée");
        // Message générique : on ne révèle pas si l'email existe
    }

    // 2. Le compte est-il verrouillé ? (anti-bruteforce hérité de TP2)
    if (user.getLockUntil() != null && LocalDateTime.now().isBefore(user.getLockUntil())) {
        throw new AccountLockedException("Compte temporairement verrouillé.");
    }

    // 3. Le timestamp est-il dans la fenêtre ±60 secondes ?
    long now = Instant.now().getEpochSecond();
    if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW_SECONDS) { // 60L
        throw new AuthenticationFailedException("Authentification échouée");
        // Protège contre les requêtes trop vieilles ou du futur
    }

    // 4. Le nonce a-t-il déjà été utilisé ? (anti-rejeu)
    if (authNonceRepository.findByUserAndNonce(user, nonce).isPresent()) {
        throw new AuthenticationFailedException("Authentification échouée");
    }

    // 5. Enregistrement du nonce (consommé immédiatement)
    AuthNonce authNonce = new AuthNonce(user, nonce,
        LocalDateTime.now().plusSeconds(NONCE_TTL_SECONDS)); // 120L
    authNonce.setConsumed(true);
    authNonceRepository.save(authNonce);

    // 6. Recalcul du HMAC côté serveur
    // (TP3 : mot de passe en clair en BDD — corrigé en TP4 avec AES-GCM)
    String plainPassword = user.getPassword();
    String message = hmacService.buildMessage(email, nonce, timestamp);
    String expectedHmac = hmacService.compute(plainPassword, message);

    // 7. Comparaison en temps constant
    if (!hmacService.compareConstantTime(expectedHmac, hmac)) {
        handleFailedAttempt(user); // incrémente compteur bruteforce
        throw new AuthenticationFailedException("Authentification échouée");
    }

    // 8. Succès : émission du token SSO (UUID, valide 15 min)
    user.setFailedAttempts(0);
    user.setLockUntil(null);
    String token = UUID.randomUUID().toString();
    user.setSessionToken(token);
    userRepository.save(user);

    return token;
}
```

### Pourquoi cet ordre de vérification ?

L'ordre est important pour des raisons de sécurité et de performance :
- On vérifie l'existence de l'utilisateur en premier pour éviter des opérations coûteuses sur des requêtes invalides.
- On vérifie le timestamp **avant** de vérifier le nonce en BDD : si le timestamp est invalide, on économise un accès BDD.
- On enregistre le nonce **avant** de calculer le HMAC pour éviter les races conditions dans le cas de requêtes concurrentes.

---

## La limite pédagogique de TP3

En TP3, pour que le serveur puisse recalculer le HMAC, il lui faut le mot de passe **en clair**. Cela signifie que le mot de passe est stocké de façon **réversible** en base de données (en clair dans TP3, même si la colonne s'appelle `password_encrypted`).

```
⚠️ Si la base fuite, les mots de passe sont exposés.
```

C'est le compromis pédagogique de TP3 : on a protégé le transit réseau, mais pas le stockage en base. TP4 résoudra ce problème avec AES-256-GCM.

---

## Récapitulatif des protections apportées par TP3

| Attaque | Protection |
|---|---|
| Interception réseau (MITM) | Le mot de passe ne transite plus jamais |
| Rejeu d'une requête capturée | Nonce unique par requête (rejeté si déjà vu) |
| Requête avec timestamp décalé | Fenêtre ±60 secondes stricte |
| Timing attack sur la comparaison | `MessageDigest.isEqual()` (temps constant) |
| Bruteforce | Hérité de TP2 : verrouillage après 5 échecs |

---

## Tests associés

```java
// Login valide avec HMAC correct
@Test
void loginShouldSucceedWithValidHmac() {
    authService.register(VALID_EMAIL, VALID_PASSWORD);
    String n = UUID.randomUUID().toString();
    long ts = Instant.now().getEpochSecond();
    String hmac = hmacService.compute(VALID_PASSWORD,
        hmacService.buildMessage(VALID_EMAIL, n, ts));
    String token = authService.login(VALID_EMAIL, n, ts, hmac);
    assertNotNull(token);
}

// Nonce déjà utilisé → rejeté
@Test
void loginShouldFailWhenNonceAlreadyUsed() {
    authService.register(VALID_EMAIL, VALID_PASSWORD);
    String n = UUID.randomUUID().toString(); long ts = nowTs();
    String hmac = validHmac(VALID_EMAIL, n, ts);

    authService.login(VALID_EMAIL, n, ts, hmac); // 1er login OK

    // 2ème tentative avec le même nonce → rejeté même avec un bon HMAC
    long ts2 = nowTs();
    String hmac2 = validHmac(VALID_EMAIL, n, ts2);
    assertThrows(AuthenticationFailedException.class,
        () -> authService.login(VALID_EMAIL, n, ts2, hmac2));
}

// Timestamp expiré → rejeté
@Test
void loginShouldFailWithExpiredTimestamp() {
    authService.register(VALID_EMAIL, VALID_PASSWORD);
    String n = UUID.randomUUID().toString();
    long expiredTs = Instant.now().getEpochSecond() - 120L; // 2 min dans le passé
    String hmac = validHmac(VALID_EMAIL, n, expiredTs);
    assertThrows(AuthenticationFailedException.class,
        () -> authService.login(VALID_EMAIL, n, expiredTs, hmac));
}

// Comparaison temps constant
@Test
void compareConstantTimeShouldReturnTrueForEqualStrings() {
    assertTrue(hmacService.compareConstantTime("abc", "abc"));
}

@Test
void compareConstantTimeShouldReturnFalseForDifferentStrings() {
    assertFalse(hmacService.compareConstantTime("abc", "xyz"));
}
```
