# TP-1
Projet login (semaine 1)

# Ordre des commit:
- v1.0-init
- v1.1-model
- v1.2-register
- v1.3-login
- v1.4-protected
- v1-tp1

## Prérequis
- Java 17
- Maven 3.x
- MySQL 8.x


Modifier `application.properties` si besoin avec tes identifiants MySQL.

## Lancer l'API
```bash
mvn spring-boot:run
```
L'API démarre sur : http://localhost:8080

## Compte de test
- Email : toto@example.com
- Mot de passe : pwd1234

## Endpoints
| Méthode | URL | Description |
|---------|-----|-------------|
| POST | /api/auth/register | Créer un compte |
| POST | /api/auth/login | Se connecter |
| GET | /api/me | Profil (token requis) |

## Analyse de sécurité TP1 – 5 risques majeurs

### 1. Mot de passe stocké en clair
Si la base de données est compromise, tous les mots de passe sont
immédiatement lisibles par l'attaquant.

### 2. Aucun chiffrement en transit
Sans HTTPS, le mot de passe voyage en clair sur le réseau.
Toute écoute réseau (sniffing) permet de le capturer.

### 3. Token non expirant
Le token de session ne expire jamais. Un token volé donne
un accès permanent au compte.

### 4. Politique de mot de passe trop faible
4 caractères minimum permet des mots de passe triviaux
(ex: "aaaa") facilement devinables par brute force.

### 5. Absence de protection contre le brute force
Aucune limitation du nombre de tentatives de connexion.
Un attaquant peut essayer des millions de mots de passe sans blocage.
