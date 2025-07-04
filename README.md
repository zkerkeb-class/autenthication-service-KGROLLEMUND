# Service d'Authentification

Ce service gère l'authentification des utilisateurs, y compris l'inscription, la connexion, la vérification d'email, la réinitialisation de mot de passe et l'authentification OAuth avec des fournisseurs externes.

## Configuration

1. Créez un fichier `.env` à la racine du projet en vous basant sur le modèle suivant :

```
PORT=3001
NODE_ENV=development
JWT_SECRET=your_jwt_secret_key_here

# URLs des services
CLIENT_URL=http://localhost:3000
AUTH_SERVICE_URL=http://localhost:3001
DB_SERVICE_URL=http://localhost:3004
NOTIFICATION_SERVICE_URL=http://localhost:3003

# Configuration de session
SESSION_SECRET=your_session_secret_key_here

# OAuth - Google
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here

# OAuth - LinkedIn
LINKEDIN_CLIENT_ID=your_linkedin_client_id_here
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret_here

# OAuth - GitHub
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
```

2. Installez les dépendances :

```bash
npm install
```

3. Démarrez le service :

```bash
npm start
```

## Configuration des fournisseurs OAuth

### Google OAuth

1. Accédez à la [Console Google Cloud](https://console.cloud.google.com/)
2. Créez un nouveau projet ou sélectionnez un projet existant
3. Allez dans "APIs & Services" > "Credentials"
4. Cliquez sur "Create Credentials" > "OAuth client ID"
5. Sélectionnez "Web application" comme type d'application
6. Ajoutez les URLs de redirection autorisées :
   - `http://localhost:3001/api/auth/google/callback` (développement)
   - `https://votre-domaine.com/api/auth/google/callback` (production)
7. Copiez le Client ID et le Client Secret dans votre fichier `.env`

### LinkedIn OAuth

1. Accédez au [Portail Développeur LinkedIn](https://www.linkedin.com/developers/)
2. Créez une nouvelle application
3. Dans la section "Auth", configurez les URLs de redirection OAuth 2.0 :
   - `http://localhost:3001/api/auth/linkedin/callback` (développement)
   - `https://votre-domaine.com/api/auth/linkedin/callback` (production)
4. Dans la section "Products", activez "Sign In with LinkedIn"
5. Copiez le Client ID et le Client Secret dans votre fichier `.env`

### GitHub OAuth

1. Accédez aux [Paramètres Développeur GitHub](https://github.com/settings/developers)
2. Cliquez sur "New OAuth App"
3. Remplissez les informations de l'application
4. Définissez l'URL de callback :
   - `http://localhost:3001/api/auth/github/callback` (développement)
   - `https://votre-domaine.com/api/auth/github/callback` (production)
5. Enregistrez l'application et copiez le Client ID et le Client Secret dans votre fichier `.env`

## APIs disponibles

### Authentification classique

- `POST /register` - Inscription d'un nouvel utilisateur
- `POST /login` - Connexion d'un utilisateur
- `POST /verify-email` - Vérification d'adresse email
- `POST /request-password-reset` - Demande de réinitialisation de mot de passe par SMS
- `POST /request-password-reset-email` - Demande de réinitialisation de mot de passe par email
- `POST /verify-reset-code` - Vérification du code de réinitialisation
- `POST /reset-password` - Réinitialisation du mot de passe
- `GET /verify` - Vérification du token JWT

### Authentification OAuth

- `GET /google` - Authentification avec Google
- `GET /google/callback` - Callback pour l'authentification Google
- `GET /linkedin` - Authentification avec LinkedIn
- `GET /linkedin/callback` - Callback pour l'authentification LinkedIn
- `GET /github` - Authentification avec GitHub
- `GET /github/callback` - Callback pour l'authentification GitHub 