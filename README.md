# Serveur d'Authentification – TP1 à TP4

## Prérequis
- Java 17
- Maven 3.x
- MySQL 8.x

---

## Lancer MySQL et configurer l'application

```bash
mysql -u root -p
CREATE DATABASE auth_db;
```

Modifier `src/main/resources/application.properties` :
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db?useSSL=false&serverTimezone=UTC
spring.datasource.username=root
spring.datasource.password=VOTRE_MOT_DE_PASSE
```

## Lancer l'API

```bash
mvn spring-boot:run
```

L'API démarre sur : http://localhost:8080

## Lancer le client Java

> Le client lourd Java (Swing/JavaFX) se lance depuis son propre module.
> Assurez-vous que l'API est démarrée avant de lancer le client.

## Compte de test

| TP  | Email               | Mot de passe       | Stockage serveur                  |
|-----|---------------------|--------------------|-----------------------------------|
| TP1 | toto@example.com    | pwd1234            | Clair                             |
| TP2 | toto@example.com    | Toto1234!@secure   | BCrypt                            |
| TP3 | toto@example.com    | Toto1234!@secure   | Clair (limite pédagogique)        |
| TP4 | toto@example.com    | Toto1234!@secure   | AES-256-GCM (v1:iv:ciphertext)   |

> **TP4** : Le compte de test est créé automatiquement au démarrage (`DataInitializer.java`).
> Le mot de passe est chiffré via `APP_MASTER_KEY` avant toute insertion en base.

---

## Endpoints

| Méthode | URL                   | Description                        |
|---------|-----------------------|------------------------------------|
| POST    | /api/auth/register    | Créer un compte                    |
| POST    | /api/auth/login       | Se connecter (HMAC depuis TP3)     |
| GET     | /api/me               | Profil (Bearer token requis)       |

---

## Tags Git

| Tag                  | Contenu                                      |
|----------------------|----------------------------------------------|
| v1.0-init            | Initialisation projet                        |
| v1.1-model           | Entité User + repository                     |
| v1.2-register        | POST /api/auth/register                      |
| v1.3-login           | POST /api/auth/login (clair)                 |
| v1.4-protected       | GET /api/me                                  |
| v1-tp1               | Finalisation TP1                             |
| v2.0-start           | Démarrage TP2                                |
| v2.1-db-migration    | password_clear → password_hash               |
| v2.2-password-policy | PasswordPolicyValidator (12 car, complexité) |
| v2.3-hashing         | BCrypt                                       |
| v2.4-lockout         | Anti brute-force (5 échecs → 2 min)          |
| v2.5-ui-strength     | Indicateur force mot de passe                |
| v2.6-sonarcloud      | SonarCloud + GitHub Actions                  |
| v2-tp2               | Finalisation TP2                             |
| v3.0-start           | Démarrage TP3                                |
| v3.1-db-nonce        | Table auth_nonce + password_encrypted        |
| v3.2-hmac-client     | Protocole HMAC côté client                   |
| v3.3-hmac-server     | Vérification HMAC côté serveur               |
| v3.4-anti-replay     | Protection anti-rejeu (nonce + timestamp)    |
| v3.5-token           | Token SSO avec expiration 15 min             |
| v3.6-tests-80        | Tests >= 15, couverture >= 80%               |
| v3-tp3               | Finalisation TP3                             |
| v4.0-start           | Démarrage TP4                                |
| v4.1-aes-gcm         | AesGcmService (AES-256-GCM) + EncryptionException |
| v4.2-register-encrypt| Chiffrement mot de passe à l'inscription     |
| v4.3-login-decrypt   | Déchiffrement au login + DataInitializer     |
| v4.4-ci-cd           | CI/CD avec APP_MASTER_KEY + blocage merge    |
| v4.5-tests-20        | 23+ tests (AesGcmServiceTest + AuthServiceTest) |
| v4-tp4               | Finalisation TP4                             |

---

## > Étapes manuelles obligatoires

### **SonarCloud (TP2 / TP3)**

> **1. Créer le projet sur SonarCloud**
> - Aller sur https://sonarcloud.io → "My Projects" → "Analyze new project"
> - Sélectionner le repository GitHub `Aichido/TP-1`
> - Récupérer votre `projectKey` et `organization`

> **2. Mettre à jour `sonar-project.properties`**
> ```properties
> sonar.projectKey=VOTRE_PROJECT_KEY
> sonar.organization=VOTRE_ORGANISATION
> ```

> **3. Configurer les secrets GitHub Actions**
> - Aller dans **GitHub → Settings → Secrets and variables → Actions**
> - Ajouter les 3 secrets suivants :
>   - `SONAR_TOKEN` — token généré sur SonarCloud (Account → Security)
>   - `SONAR_PROJECT_KEY` — la clé de votre projet SonarCloud
>   - `SONAR_ORGANIZATION` — votre organisation SonarCloud

> **4. Activer le blocage de merge si CI échoue**
> - Aller dans **GitHub → Settings → Branches → Branch protection rules**
> - Sélectionner la branche `main`
> - Cocher **"Require status checks to pass before merging"**
> - Ajouter le check `build` (nom du job dans `ci.yml`)

---

## Analyse de sécurité TP1 – 5 risques majeurs

### 1. Mot de passe stocké en clair
Si la base de données est compromise, tous les mots de passe sont immédiatement lisibles.

### 2. Aucun chiffrement en transit
Sans HTTPS, le mot de passe voyage en clair sur le réseau. Toute écoute réseau permet de le capturer.

### 3. Token non expirant
Le token de session ne expire jamais. Un token volé donne un accès permanent au compte.

### 4. Politique de mot de passe trop faible
4 caractères minimum permet des mots de passe triviaux facilement devinables.

### 5. Absence de protection contre le brute force
Aucune limitation du nombre de tentatives. Un attaquant peut essayer des millions de mots de passe sans blocage.

---

## Analyse de sécurité TP2 – Améliorations et faiblesse résiduelle

- **BCrypt** : les mots de passe ne sont plus stockés en clair.
- **Politique stricte** : 12 caractères min, complexité imposée.
- **Anti brute-force** : verrouillage 2 min après 5 échecs.

**Faiblesse résiduelle** : le mot de passe (ou son hash) circule encore dans la requête de login et reste rejouable si une requête est capturée. TP3 corrige cela.

### SonarCloud TP2

> **Quality Gate** : à vérifier après configuration des secrets.
> **Couverture** : mesurée via JaCoCo (`mvn verify` → `target/site/jacoco/index.html`).

---

## > Étapes manuelles obligatoires TP4

> **1. Définir la Master Key en variable d'environnement**
> ```bash
> # Linux / macOS
> export APP_MASTER_KEY="votre_cle_secrete_longue_et_aleatoire"
> # Windows PowerShell
> $env:APP_MASTER_KEY="votre_cle_secrete_longue_et_aleatoire"
> ```
> La clé doit avoir au moins 32 caractères aléatoires. Elle ne doit jamais être dans le code ou dans Git.

> **2. Ajouter `APP_MASTER_KEY` comme secret GitHub Actions**
> - Aller dans **GitHub → Settings → Secrets and variables → Actions**
> - Ajouter : `APP_MASTER_KEY` avec votre valeur de production
> - La CI injecte automatiquement une clé fictive pour les tests (`test_master_key_for_ci_only`)

> **3. Configurer le blocage de merge si CI échoue**
> - Aller dans **GitHub → Settings → Branches → Branch protection rules**
> - Sélectionner la branche `main`
> - Cocher **"Require status checks to pass before merging"**
> - Ajouter le check `build`
> - Cocher **"Require branches to be up to date before merging"**

> **4. Réinitialiser la base MySQL pour TP4**
> ```sql
> -- Les anciens mots de passe en clair (TP3) ne peuvent pas être déchiffrés en TP4.
> -- Vider la table et redémarrer l'application pour recréer les comptes chiffrés.
> DELETE FROM users;
> DELETE FROM auth_nonce;
> ```

---

## Analyse de sécurité TP3 – Protocole HMAC + anti-rejeu

- **Aucun mot de passe ne circule** sur le réseau (ni en clair, ni haché).
- Le client prouve qu'il connaît le secret sans l'envoyer.
- **Nonce** : empêche la réutilisation d'une même requête.
- **Timestamp** (±60 s) : limite la durée d'une attaque par rejeu capturé.
- **Comparaison en temps constant** : évite les attaques par timing.

**Limite pédagogique** : Le mot de passe est stocké de façon réversible en base pour servir de clé HMAC. En industrie, on éviterait ce stockage réversible — c'est le compromis pédagogique de TP3, corrigé en TP4 avec AES-GCM.

---

## Analyse de sécurité TP4 – Master Key AES-GCM

- **AES-256-GCM** : chiffrement symétrique AEAD (confidentialité + intégrité en un seul algo).
- **IV aléatoire** : 96 bits générés via `SecureRandom` à chaque chiffrement → deux chiffrements du même texte sont toujours différents.
- **Intégrité garantie** : le tag GCM (128 bits) détecte toute modification du chiffré.
- **Clé hors code** : `APP_MASTER_KEY` injectée uniquement par variable d'environnement.
- **CI/CD** : GitHub Actions bloque tout merge si un test échoue ou si le Quality Gate SonarCloud est rouge.

**Résumé de la progression de sécurité :**

| TP  | Transit      | Stockage              | Rejeu    |
|-----|-------------|----------------------|----------|
| TP1 | Clair        | Clair                | Possible |
| TP2 | Clair        | BCrypt               | Possible |
| TP3 | HMAC (zéro) | Clair réversible     | Bloqué   |
| TP4 | HMAC (zéro) | AES-256-GCM chiffré  | Bloqué   |
