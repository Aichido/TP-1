# TP5 — Changement de mot de passe sécurisé

## Le problème que TP5 résout

À la fin de TP4, un utilisateur n'a aucun moyen de changer son mot de passe. C'est un manque critique : en cas de compromission suspectée, la seule solution est l'intervention manuelle en base de données.

TP5 ajoute un endpoint **POST /api/auth/change-password** qui permet à un utilisateur authentifié de changer son mot de passe **sans jamais le faire circuler en clair** sur le réseau, tout en maintenant toutes les protections construites dans les TPs précédents.

---

## Deux défis de sécurité

### Défi 1 — Prouver la connaissance de l'ancien mot de passe

Pour changer son mot de passe, l'utilisateur doit prouver qu'il connaît l'ancien. On ne peut pas simplement envoyer l'ancien mot de passe en clair : ce serait régresser par rapport à TP3.

**Solution :** On réutilise le protocole HMAC de TP3. L'utilisateur calcule :

```
oldHmac = HMAC-SHA256(ancienMotDePasse, email:nonce:timestamp)
```

Le serveur déchiffre l'ancien mot de passe (AES-GCM de TP4), recalcule le HMAC et compare en temps constant. Si les deux correspondent, l'utilisateur a prouvé sa connaissance **sans jamais transmettre le mot de passe**.

### Défi 2 — Invalider la session après changement

Si un attaquant a volé un token SSO, il peut l'utiliser tant qu'il est valide. Après un changement de mot de passe, le token actuel doit être **immédiatement invalidé**.

**Solution :** On met `sessionToken = null` après le changement. Toute requête utilisant l'ancien token recevra une erreur 401. L'utilisateur doit se reconnecter avec le nouveau mot de passe.

---

## Protocole complet

```
Client                                    Serveur
  │                                          │
  │  1. Génère nonce (UUID) + timestamp      │
  │  2. Calcule oldHmac:                     │
  │     HMAC-SHA256(ancienMDP,               │
  │       email:nonce:timestamp)             │
  │                                          │
  │  POST /api/auth/change-password          │
  │  Authorization: Bearer <token>           │
  │  {nonce, timestamp, oldHmac,             │
  │   newPassword}          ─────────────►  │
  │                                          │  3. Vérifie Bearer token → identifie user
  │                                          │  4. Vérifie compte non verrouillé
  │                                          │  5. Vérifie |now - timestamp| ≤ 60 s
  │                                          │  6. Vérifie nonce non déjà utilisé
  │                                          │  7. Enregistre nonce (consommé)
  │                                          │  8. Déchiffre AES-GCM → ancienMDP
  │                                          │  9. Recalcule HMAC(ancienMDP, email:nonce:ts)
  │                                          │ 10. Comparaison en temps constant
  │                                          │ 11. Valide politique du nouveau MDP
  │                                          │ 12. Chiffre AES-GCM(nouveauMDP)
  │                                          │ 13. Sauvegarde + sessionToken = null
  │  ◄─────────── 200 OK {message}           │
  │                                          │
  │  Reconnexion nécessaire                  │
```

---

## Étape 1 — Le DTO `ChangePasswordRequest`

```java
// src/main/java/com/example/auth/dto/ChangePasswordRequest.java
public class ChangePasswordRequest {
    private String nonce;       // UUID unique (anti-rejeu)
    private long   timestamp;   // Unix en secondes (fenêtre ±60 s)
    private String oldHmac;     // HMAC-SHA256(ancienMDP, email:nonce:timestamp)
    private String newPassword; // Nouveau mot de passe en clair
}
```

Le `nonce` et le `timestamp` servent à la protection anti-rejeu, exactement comme au login (TP3). Un attaquant qui capture la requête ne peut pas la rejouer : le nonce est marqué consommé côté serveur.

---

## Étape 2 — La méthode `AuthService.changePassword()`

```java
public void changePassword(String token, String nonce, long timestamp,
                           String oldHmac, String newPassword) {

    // 1. Identification via token Bearer
    User user = getUserByToken(token);

    // 2. Compte non verrouillé ?
    if (user.getLockUntil() != null && LocalDateTime.now().isBefore(user.getLockUntil())) {
        throw new AccountLockedException("Compte temporairement verrouillé.");
    }

    // 3. Fenêtre temporelle ±60 secondes
    long now = Instant.now().getEpochSecond();
    if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW_SECONDS) {
        throw new AuthenticationFailedException("Vérification échouée");
    }

    // 4. Anti-rejeu : nonce déjà vu ?
    if (authNonceRepository.findByUserAndNonce(user, nonce).isPresent()) {
        throw new AuthenticationFailedException("Vérification échouée");
    }
    authNonceRepository.save(new AuthNonce(user, nonce, ...));

    // 5. Déchiffrement AES-GCM → ancien mot de passe en clair
    String plainOldPassword = aesGcmService.decrypt(user.getPassword());

    // 6. Vérification HMAC en temps constant
    String message = hmacService.buildMessage(user.getEmail(), nonce, timestamp);
    String expectedHmac = hmacService.compute(plainOldPassword, message);
    if (!hmacService.compareConstantTime(expectedHmac, oldHmac)) {
        handleFailedAttempt(user); // compteur d'échecs + verrouillage
        throw new AuthenticationFailedException("Vérification échouée");
    }

    // 7. Validation politique du nouveau mot de passe
    passwordPolicyValidator.validate(newPassword);

    // 8. Chiffrement AES-GCM du nouveau mot de passe
    String encryptedNewPassword = aesGcmService.encrypt(newPassword);

    // 9. Mise à jour + invalidation du token (force reconnexion)
    user.setPassword(encryptedNewPassword);
    user.setSessionToken(null);
    user.setFailedAttempts(0);
    userRepository.save(user);
}
```

---

## Étape 3 — L'endpoint `AuthController`

```java
@PostMapping("/api/auth/change-password")
public ResponseEntity<Map<String, String>> changePassword(
        @RequestHeader(value = "Authorization", required = false) String authorization,
        @RequestBody ChangePasswordRequest request) {
    String token = extractToken(authorization);
    authService.changePassword(
        token,
        request.getNonce(),
        request.getTimestamp(),
        request.getOldHmac(),
        request.getNewPassword()
    );
    return ResponseEntity.ok(Map.of(
        "message", "Mot de passe modifié avec succès. Veuillez vous reconnecter."));
}
```

---

## Étape 4 — Tests (7 cas)

### Cas 17 — Changement réussi

```java
@Test
void changePasswordShouldSucceedWithValidHmac() {
    String token = registerAndLogin();
    String n = nonce(); long ts = nowTs();
    assertDoesNotThrow(() ->
        authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), NEW_PASSWORD));
}
```

### Cas 18 — Token invalidé après changement

```java
@Test
void changePasswordShouldInvalidateSessionToken() {
    String token = registerAndLogin();
    String n = nonce(); long ts = nowTs();
    authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), NEW_PASSWORD);
    // L'ancien token ne doit plus fonctionner
    assertThrows(AuthenticationFailedException.class,
        () -> authService.getUserByToken(token));
}
```

### Cas 19 — HMAC invalide

```java
@Test
void changePasswordShouldFailWithInvalidHmac() {
    String token = registerAndLogin();
    String n = nonce(); long ts = nowTs();
    assertThrows(AuthenticationFailedException.class,
        () -> authService.changePassword(token, n, ts, "bad_hmac", NEW_PASSWORD));
}
```

### Cas 20 — Nouveau mot de passe trop court

```java
@Test
void changePasswordShouldFailWhenNewPasswordTooShort() {
    String token = registerAndLogin();
    String n = nonce(); long ts = nowTs();
    assertThrows(InvalidInputException.class,
        () -> authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), "Short1!"));
}
```

### Cas 21 — Timestamp expiré

```java
@Test
void changePasswordShouldFailWithExpiredTimestamp() {
    String token = registerAndLogin();
    String n = nonce();
    long expiredTs = Instant.now().getEpochSecond() - 120L;
    assertThrows(AuthenticationFailedException.class,
        () -> authService.changePassword(token, n, expiredTs,
            changeHmac(VALID_EMAIL, n, expiredTs), NEW_PASSWORD));
}
```

### Cas 22 — Nonce déjà utilisé

```java
@Test
void changePasswordShouldFailWhenNonceAlreadyUsed() {
    String token = registerAndLogin();
    String n = nonce(); long ts = nowTs();
    // Premier changement consomme le nonce
    authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), NEW_PASSWORD);
    // Réutilisation du même nonce → refus
    // (test réalisé sur un autre compte pour avoir un token valide)
    ...
}
```

### Cas 23 — Token invalide

```java
@Test
void changePasswordShouldFailWithInvalidToken() {
    String n = nonce(); long ts = nowTs();
    assertThrows(AuthenticationFailedException.class,
        () -> authService.changePassword("invalid-token", n, ts, "hmac", NEW_PASSWORD));
}
```

### Cas 24 — Login avec le nouveau mot de passe

```java
@Test
void loginShouldSucceedWithNewPasswordAfterChange() {
    String token = registerAndLogin();
    String n = nonce(); long ts = nowTs();
    authService.changePassword(token, n, ts, changeHmac(VALID_EMAIL, n, ts), NEW_PASSWORD);

    // Connexion avec le nouveau mot de passe
    String n2 = nonce(); long ts2 = nowTs();
    String newHmac = hmacService.compute(NEW_PASSWORD,
        hmacService.buildMessage(VALID_EMAIL, n2, ts2));
    String newToken = authService.login(VALID_EMAIL, n2, ts2, newHmac);
    assertNotNull(newToken);
}
```

---

## Exemple d'appel avec curl

### 1. Connexion pour obtenir un token

```bash
NONCE=$(uuidgen)
TS=$(date +%s)
HMAC=$(echo -n "user@example.com:$NONCE:$TS" | openssl dgst -sha256 -hmac "MonMotDePasse1!@" -binary | base64)

curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"user@example.com\",\"nonce\":\"$NONCE\",\"timestamp\":$TS,\"hmac\":\"$HMAC\"}"
```

### 2. Changement de mot de passe

```bash
TOKEN="<token-obtenu-ci-dessus>"
NONCE2=$(uuidgen)
TS2=$(date +%s)
OLD_HMAC=$(echo -n "user@example.com:$NONCE2:$TS2" | openssl dgst -sha256 -hmac "MonMotDePasse1!@" -binary | base64)

curl -X POST http://localhost:8080/api/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"nonce\": \"$NONCE2\",
    \"timestamp\": $TS2,
    \"oldHmac\": \"$OLD_HMAC\",
    \"newPassword\": \"NouveauMDP2!@secure\"
  }"
```

**Réponse attendue :**

```json
{
  "message": "Mot de passe modifié avec succès. Veuillez vous reconnecter."
}
```

### 3. Vérification : l'ancien token est invalidé

```bash
curl http://localhost:8080/api/me \
  -H "Authorization: Bearer $TOKEN"
# → 401 Unauthorized
```

---

## Bilan de sécurité TP5

| Menace | Protection |
|--------|-----------|
| Changement par un tiers (vol de token seul) | HMAC de l'ancien MDP obligatoire |
| Replay de la requête de changement | Nonce UUID consommé + timestamp ±60 s |
| Timing attack sur la vérification | Comparaison HMAC en temps constant |
| Mot de passe faible comme nouveau MDP | Politique TP2 appliquée obligatoirement |
| Réutilisation du token après changement | `sessionToken = null` → reconnexion forcée |
| Bruteforce du HMAC | Compteur d'échecs + verrouillage 2 min (TP2) |
| Nouveau MDP exposé en base | Chiffrement AES-256-GCM (TP4) |

---

## Récapitulatif des TPs

| TP | Feature principale | Faiblesse résolue |
|----|-------------------|-------------------|
| TP1 | API REST basique | — (point de départ) |
| TP2 | Hachage BCrypt + politique MDP + anti-bruteforce | Mots de passe en clair en BDD |
| TP3 | Protocole HMAC + nonce/timestamp anti-rejeu | MDP transmis en clair sur le réseau |
| TP4 | Chiffrement AES-256-GCM au repos | MDP déchiffrable si BDD volée |
| TP5 | Changement de MDP sécurisé + invalidation token | Impossibilité de faire évoluer ses credentials |

L'architecture finale offre une protection à chaque niveau : transit (HMAC), stockage (AES-GCM), politique (TP2), cycle de vie (TP5).
