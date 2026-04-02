# TP4 — Chiffrement AES-256-GCM : protection des mots de passe au repos

## Le problème que TP4 résout

À la fin de TP3, on a un protocole HMAC solide : le mot de passe ne transite plus sur le réseau. Mais le serveur doit connaître le mot de passe en clair pour recalculer le HMAC. Le mot de passe est donc stocké tel quel en base de données.

```
⚠️ En TP3 : si la base de données est volée, tous les mots de passe sont exposés.
```

TP4 résout cela en **chiffrant** les mots de passe au repos avec AES-256-GCM. Le chiffrement est **réversible** (contrairement au hachage de TP2), ce qui est nécessaire pour le protocole HMAC de TP3, mais la clé de déchiffrement est séparée de la base de données.

---

## Comprendre AES-256-GCM

### AES (Advanced Encryption Standard)

AES est l'algorithme de chiffrement symétrique le plus utilisé au monde. "256" signifie que la clé fait 256 bits (32 octets), ce qui offre une sécurité très élevée.

### GCM (Galois/Counter Mode)

GCM est un mode de fonctionnement d'AES qui en fait un chiffrement **AEAD** (Authenticated Encryption with Associated Data). Cela signifie qu'il fournit simultanément :

- **Confidentialité** : le texte chiffré ne révèle rien sur le texte clair.
- **Intégrité** : si le chiffré est modifié (même d'un seul bit), le déchiffrement échoue avec une erreur détectable.

### L'IV (vecteur d'initialisation)

L'IV est un nombre aléatoire de 96 bits (12 octets) généré à chaque chiffrement. Il garantit que le même mot de passe chiffré deux fois donne deux chiffrés complètement différents (sécurité sémantique).

> **Règle d'or :** Ne jamais réutiliser le même IV avec la même clé. Ici, on génère un IV aléatoire à chaque fois via `SecureRandom`.

### Le tag GCM

GCM produit un **tag d'authentification** de 128 bits en plus du chiffré. Ce tag est vérifié lors du déchiffrement. Toute modification du chiffré invalide le tag et provoque une `AEADBadTagException`.

---

## Étape 1 — La Server Master Key (SMK)

La clé de chiffrement est appelée **Server Master Key** (SMK). Elle est injectée via une variable d'environnement `APP_MASTER_KEY`. Elle ne doit **jamais** être codée en dur dans le code source.

### Dans `application.properties`

```properties
# src/main/resources/application.properties
app.master-key=${APP_MASTER_KEY}
```

### Dans `application-test.properties` (pour les tests)

```properties
# src/main/resources/application-test.properties
app.master-key=test_master_key_for_ci_only
```

En production, on injecte la valeur réelle via une variable d'environnement :

```bash
APP_MASTER_KEY=une_clé_très_longue_et_aléatoire ./mvnw spring-boot:run
```

---

## Étape 2 — L'`AesGcmService`

### Dérivation de la clé

La SMK fournie peut avoir n'importe quelle longueur, mais AES-256 requiert exactement 32 octets. On dérive une clé de taille fixe via SHA-256 :

```java
// src/main/java/com/example/auth/service/AesGcmService.java

private byte[] deriveKey256(String rawKey) {
    try {
        return MessageDigest.getInstance("SHA-256")
            .digest(rawKey.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
        throw new IllegalStateException("Impossible de dériver la clé AES-256", e);
    }
}
```

`SHA-256` produit toujours exactement 32 octets, quelle que soit la longueur de l'entrée. En production, on préférerait PBKDF2 ou Argon2 pour une dérivation plus robuste, mais SHA-256 suffit ici car la SMK est déjà aléatoire.

### Initialisation et vérification de la clé

```java
public AesGcmService(@Value("${app.master-key}") String rawKey) {
    if (rawKey == null || rawKey.isBlank()) {
        throw new IllegalStateException(
            "APP_MASTER_KEY est obligatoire. L'application ne peut pas démarrer sans clé maître.");
    }
    this.masterKey = new SecretKeySpec(deriveKey256(rawKey), "AES");
}
```

**Point important :** On utilise `@Value("${app.master-key}")` pour que Spring injecte la valeur depuis `application.properties`. Le constructeur lève une `IllegalStateException` si la clé est absente — l'application refuse de démarrer, ce qui est le comportement voulu (fail-fast).

---

### La méthode `encrypt()`

```java
private static final String ALGO = "AES/GCM/NoPadding";
private static final int GCM_IV_LENGTH = 12;  // 96 bits — recommandé NIST SP 800-38D
private static final int GCM_TAG_BITS  = 128; // tag 128 bits

public String encrypt(String plaintext) {
    try {
        // 1. Générer un IV aléatoire de 96 bits
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // 2. Initialiser le chiffrement AES-GCM
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // 3. Chiffrer
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // 4. Format de sortie : "v1:Base64(iv):Base64(ciphertext)"
        return "v1:"
            + Base64.getEncoder().encodeToString(iv) + ":"
            + Base64.getEncoder().encodeToString(ciphertext);
    } catch (Exception e) {
        throw new EncryptionException("Échec du chiffrement AES-GCM", e);
    }
}
```

**Le format `v1:iv:ciphertext` :**
- `v1` est le numéro de version du format. Si on change l'algorithme dans le futur, on utilisera `v2`, ce qui permet de gérer la migration des données.
- L'IV est stocké avec le chiffré car on en a besoin pour déchiffrer. Il n'est pas secret.
- Le `ciphertext` inclut le tag GCM de 128 bits à la fin (ajouté automatiquement par Java).

**Pourquoi `SecureRandom` et pas `Random` ?**
`java.util.Random` est un générateur pseudo-aléatoire **prévisible** à partir de sa graine. `java.security.SecureRandom` utilise des sources d'entropie du système d'exploitation et est cryptographiquement sûr.

---

### La méthode `decrypt()`

```java
public String decrypt(String encrypted) {
    // 1. Vérifier le format
    if (encrypted == null || !encrypted.startsWith("v1:")) {
        throw new EncryptionException("Format chiffré invalide ou version non supportée");
    }
    try {
        // 2. Découper les 3 parties
        String[] parts = encrypted.split(":", 3);
        if (parts.length != 3) {
            throw new EncryptionException("Format chiffré invalide : attendu v1:iv:ciphertext");
        }
        byte[] iv         = Base64.getDecoder().decode(parts[1]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

        // 3. Initialiser le déchiffrement avec le MÊME iv
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        // 4. Déchiffrer (vérifie automatiquement le tag GCM)
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);

    } catch (AEADBadTagException e) {
        // Le tag GCM est invalide : le chiffré a été modifié ou la clé est mauvaise
        throw new EncryptionException("Intégrité du chiffré compromise (tag invalide)", e);
    } catch (EncryptionException e) {
        throw e;
    } catch (Exception e) {
        throw new EncryptionException("Échec du déchiffrement AES-GCM", e);
    }
}
```

**L'`AEADBadTagException` :** C'est l'exception levée par Java quand le tag GCM ne correspond pas. Cela arrive si :
- Le chiffré a été altéré (attaque, corruption).
- La clé de déchiffrement est différente de la clé de chiffrement.
- L'IV utilisé pour déchiffrer est différent de celui utilisé pour chiffrer.

On attrape cette exception spécifiquement pour donner un message d'erreur précis.

---

## Étape 3 — Intégration dans `AuthService`

### À l'inscription (chiffrement)

```java
// src/main/java/com/example/auth/service/AuthService.java

public User register(String email, String password) {
    // ... validation email et politique mot de passe ...

    // TP4 : chiffrement AES-256-GCM avant stockage
    String encryptedPassword = aesGcmService.encrypt(password);
    User user = new User(email, encryptedPassword);
    userRepository.save(user);
    return user;
}
```

Ce qui est stocké en base ressemble à :
```
v1:dGhpcyBpcw==:YWZha2VjaXBoZXJ0ZXh0aGVyZQ==
```

Jamais le mot de passe en clair.

### Au login (déchiffrement)

```java
public String login(String email, String nonce, long timestamp, String hmac) {
    // ... vérifications email, verrouillage, timestamp, nonce ...

    // TP4 : déchiffrement pour récupérer le mot de passe (clé HMAC)
    String plainPassword = aesGcmService.decrypt(user.getPassword());

    // Recalcul HMAC côté serveur
    String message = hmacService.buildMessage(email, nonce, timestamp);
    String expectedHmac = hmacService.compute(plainPassword, message);

    // Comparaison en temps constant
    if (!hmacService.compareConstantTime(expectedHmac, hmac)) {
        handleFailedAttempt(user);
        throw new AuthenticationFailedException("Authentification échouée");
    }

    // Succès : émettre token SSO
    String token = UUID.randomUUID().toString();
    user.setSessionToken(token);
    userRepository.save(user);
    return token;
}
```

Le mot de passe déchiffré (`plainPassword`) n'est utilisé que le temps du calcul HMAC, en mémoire. Il n'est jamais loggué ni renvoyé dans une réponse HTTP.

---

## Étape 4 — Le `DataInitializer`

Pour faciliter les tests manuels, on crée un compte de test au démarrage de l'application (hors profil test) :

```java
// src/main/java/com/example/auth/DataInitializer.java

@Component
@Profile("!test") // Ne s'exécute pas pendant les tests JUnit
public class DataInitializer implements ApplicationRunner {

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.findByEmail("toto@example.com").isEmpty()) {
            try {
                // Le mot de passe est automatiquement chiffré via AES-GCM
                authService.register("toto@example.com", "Toto1234!@secure");
                logger.info("Compte de test créé : toto@example.com");
            } catch (Exception e) {
                logger.warn("Impossible de créer le compte de test : {}", e.getMessage());
            }
        }
    }
}
```

**Pourquoi `@Profile("!test")` ?** Le profil `test` est activé lors des tests JUnit via `@ActiveProfiles("test")`. Sans ce filtre, le `DataInitializer` s'exécuterait aussi pendant les tests et pourrait interférer.

---

## Étape 5 — CI/CD avec injection de la Master Key

En CI/CD (GitHub Actions), la SMK est injectée via un secret du dépôt :

```yaml
# .github/workflows/ci.yml
- name: Build and test
  env:
    APP_MASTER_KEY: test_master_key_for_ci_only
  run: ./mvnw test
```

Ce secret est différent de la clé de production. En production, la clé réelle est stockée dans un gestionnaire de secrets (HashiCorp Vault, AWS Secrets Manager, etc.) et injectée au démarrage du serveur.

---

## Sécurité sémantique : démonstration concrète

Grâce à l'IV aléatoire, chiffrer deux fois le même mot de passe donne deux chiffrés complètement différents :

```java
String enc1 = aesGcmService.encrypt("MonMotDePasse1!");
String enc2 = aesGcmService.encrypt("MonMotDePasse1!");

// enc1 ≠ enc2, mais les deux déchiffrent bien vers "MonMotDePasse1!"
System.out.println(enc1); // v1:abc123...:xyz789...
System.out.println(enc2); // v1:def456...:uvw012...
```

Cela signifie qu'un attaquant qui vole la base ne peut pas déterminer si deux utilisateurs ont le même mot de passe en comparant les chiffrés.

---

## Récapitulatif de la progression de sécurité sur les 4 TPs

| TP | En transit | Au repos | Anti-rejeu | Note |
|---|---|---|---|---|
| TP1 | Mot de passe en clair | En clair | Non | Aucune sécurité |
| TP2 | Mot de passe en clair | BCrypt (hash) | Non | Hash non réversible mais transit vulnérable |
| TP3 | HMAC (zéro transmission) | En clair réversible | Nonce + timestamp | Transit sécurisé mais BDD vulnérable |
| TP4 | HMAC (zéro transmission) | AES-256-GCM chiffré | Nonce + timestamp | Sécurité industrielle complète |

---

## Tests associés

### `AesGcmServiceTest.java` — 6 tests unitaires

```java
// 1. Round-trip : chiffrement → déchiffrement = texte original
@Test
void encryptDecryptShouldReturnOriginalPassword() {
    String plain = "ValidPass1!@secure";
    assertEquals(plain, service.decrypt(service.encrypt(plain)));
}

// 2. Le chiffré est différent du texte en clair
@Test
void encryptedPasswordShouldDifferFromPlaintext() {
    String plain = "ValidPass1!@secure";
    String encrypted = service.encrypt(plain);
    assertNotEquals(plain, encrypted);
    assertTrue(encrypted.startsWith("v1:"), "Le format doit commencer par 'v1:'");
}

// 3. Déchiffrement KO si le chiffré est modifié (intégrité GCM)
@Test
void decryptShouldFailWithTamperedCiphertext() {
    String encrypted = service.encrypt("password123");
    String[] parts = encrypted.split(":", 3);

    // Modifier le dernier octet du ciphertext (invalide le tag GCM)
    byte[] ctBytes = Base64.getDecoder().decode(parts[2]);
    ctBytes[ctBytes.length - 1] ^= 0xFF;
    String tampered = parts[0] + ":" + parts[1] + ":"
        + Base64.getEncoder().encodeToString(ctBytes);

    assertThrows(EncryptionException.class, () -> service.decrypt(tampered));
}

// 4. Démarrage KO si APP_MASTER_KEY absente
@Test
void constructionShouldFailWithBlankKey() {
    assertThrows(IllegalStateException.class, () -> new AesGcmService(""));
    assertThrows(IllegalStateException.class, () -> new AesGcmService("   "));
}

// 5. IV aléatoire : même clair → chiffrés différents (sécurité sémantique)
@Test
void encryptShouldProduceDifferentCiphertextEachTime() {
    String plain = "SamePassword1!@x";
    String enc1 = service.encrypt(plain);
    String enc2 = service.encrypt(plain);
    assertNotEquals(enc1, enc2);
    // Les deux doivent néanmoins déchiffrer correctement
    assertEquals(plain, service.decrypt(enc1));
    assertEquals(plain, service.decrypt(enc2));
}

// 6. Format invalide → EncryptionException
@Test
void decryptShouldFailWithInvalidFormat() {
    assertThrows(EncryptionException.class, () -> service.decrypt("not-encrypted-at-all"));
    assertThrows(EncryptionException.class, () -> service.decrypt(null));
    assertThrows(EncryptionException.class, () -> service.decrypt("v1:onlyonepart"));
}
```

**Pourquoi ces tests sont importants :**
- Le test 3 (altération) est crucial : il prouve que GCM détecte les modifications. Sans GCM (avec AES-CBC par exemple), un chiffré altéré déchiffrerait silencieusement en donnant du "garbage" — c'est dangereux.
- Le test 5 (IV aléatoire) prouve la sécurité sémantique : on ne peut pas déduire quels utilisateurs ont le même mot de passe.
- Le test 4 (fail-fast) prouve que l'application refuse de démarrer sans clé, évitant un démarrage en mode non sécurisé.
