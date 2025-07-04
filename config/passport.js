const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LinkedInStrategy = require('./linkedin-strategy');
const GitHubStrategy = require('passport-github2').Strategy;
const axios = require('axios');
const dotenv = require('dotenv');

dotenv.config(); 

// URL du service de base de données
const DB_SERVICE_URL = process.env.DB_SERVICE_URL;

// Affichage des configurations (sans les secrets)
console.log('Configuration OAuth:');
console.log('- Google Client ID configuré:', !!process.env.GOOGLE_CLIENT_ID);
console.log('- LinkedIn Client ID configuré:', !!process.env.LINKEDIN_CLIENT_ID);
console.log('- GitHub Client ID configuré:', !!process.env.GITHUB_CLIENT_ID);



// Sérialisation de l'utilisateur pour la session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Désérialisation de l'utilisateur à partir de la session
passport.deserializeUser(async (id, done) => {
  try {
    // Récupérer l'utilisateur depuis le service de base de données
    const response = await axios.get(`${DB_SERVICE_URL}/users/${id}`);
    done(null, response.data);
  } catch (error) {
    done(error, null);
  }
});

// Fonction pour traiter le profil utilisateur
const processUserProfile = async (profile, done) => {
  try {
    // Vérifier si l'utilisateur existe déjà
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
    
    if (!email) {
      return done(new Error('Email non disponible dans le profil'), null);
    }
    
    try {
      console.log(`Tentative d'authentification OAuth pour l'email: ${email} avec le provider: ${profile.provider}`);
      
      // Utiliser le nouvel endpoint Account pour créer/mettre à jour l'utilisateur
      const response = await axios.post(`${DB_SERVICE_URL}/api/accounts/oauth/user`, {
        name: profile.displayName || `${profile.name?.givenName || ''} ${profile.name?.familyName || ''}`,
        email,
        provider: profile.provider,
        providerAccountId: profile.id
      });
      
      console.log('Réponse du service de base de données pour OAuth:', response.data);
      
      return done(null, response.data.user);
    } catch (error) {
      console.error('Erreur lors du traitement OAuth:', error.response?.data || error.message);
      
      // Afficher plus de détails sur l'erreur
      if (error.response) {
        console.error('Status:', error.response.status);
        console.error('Données d\'erreur:', error.response.data);
      }
      
      return done(error, null);
    }
  } catch (error) {
    console.error('Erreur globale OAuth:', error);
    return done(error, null);
  }
};

// Utilise des valeurs par défaut si les identifiants ne sont pas configurés
const googleClientID = process.env.GOOGLE_CLIENT_ID || 'test-client-id';
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || 'test-client-secret';
const linkedinClientID = process.env.LINKEDIN_CLIENT_ID || 'test-client-id';
const linkedinClientSecret = process.env.LINKEDIN_CLIENT_SECRET || 'test-client-secret';
const githubClientID = process.env.GITHUB_CLIENT_ID || 'test-client-id';
const githubClientSecret = process.env.GITHUB_CLIENT_SECRET || 'test-client-secret';

// Toujours créer les stratégies, même avec des identifiants factices
// Stratégie Google
passport.use(new GoogleStrategy({
  clientID: googleClientID,
  clientSecret: googleClientSecret,
  callbackURL: "http://localhost:3001/api/auth/google/callback",
  proxy: true
}, (accessToken, refreshToken, profile, done) => {
  if (googleClientID === 'test-client-id') {
    console.warn('⚠️ Utilisation d\'identifiants Google de test. L\'authentification ne fonctionnera pas réellement.');
    // Simuler un utilisateur pour le développement local
    const mockUser = {
      id: '123456',
      name: 'Test User',
      email: 'test@example.com'
    };
    return done(null, mockUser);
  }
  processUserProfile(profile, done);
}));

// Stratégie LinkedIn avec OpenID Connect
passport.use(new LinkedInStrategy({
  clientID: linkedinClientID,
  clientSecret: linkedinClientSecret,
  callbackURL: `http://localhost:3001/api/auth/linkedin/callback`,
  scope: ['openid', 'profile', 'email'],
  passReqToCallback: true,
  proxy: true,
  profileFields: ['id', 'first-name', 'last-name', 'email-address'],
  state: true
}, (req, accessToken, refreshToken, profile, done) => {
  console.log('=== LINKEDIN DEBUG ===');
  console.log('Request headers:', req.headers);
  console.log('Access Token:', accessToken);
  console.log('Refresh Token:', refreshToken);
  console.log('Profile brut:', JSON.stringify(profile, null, 2));
  console.log('=== END LINKEDIN DEBUG ===');
  
  if (linkedinClientID === 'test-client-id') {
    console.warn('⚠️ Utilisation d\'identifiants LinkedIn de test. L\'authentification ne fonctionnera pas réellement.');
    // Simuler un utilisateur pour le développement local
    const mockUser = {
      id: '123456',
      name: 'Test User',
      email: 'test@example.com'
    };
    return done(null, mockUser);
  }
  
  // Modification pour gérer manuellement le profil si nécessaire
  try {
    if (!profile || !profile.id) {
      console.error('Profil LinkedIn incomplet ou manquant');
      return done(new Error('Profil LinkedIn incomplet ou manquant'), null);
    }
    
    // Créer un profil minimal si nécessaire
    if (!profile.emails || !profile.emails.length) {
      console.warn('Email manquant dans le profil LinkedIn, ajout d\'un email basé sur l\'ID');
      profile.emails = [{ value: `${profile.id}@linkedin.example.com` }];
    }
    
    processUserProfile(profile, done);
  } catch (error) {
    console.error('Erreur lors du traitement du profil LinkedIn:', error);
    return done(error, null);
  }
}));

// Stratégie GitHub
passport.use(new GitHubStrategy({
  clientID: githubClientID,
  clientSecret: githubClientSecret,
  callbackURL: `http://localhost:3001/api/auth/github/callback`,
  scope: ['user:email'],
  proxy: true
}, (accessToken, refreshToken, profile, done) => {
  if (githubClientID === 'test-client-id') {
    console.warn('⚠️ Utilisation d\'identifiants GitHub de test. L\'authentification ne fonctionnera pas réellement.');
    // Simuler un utilisateur pour le développement local
    const mockUser = {
      id: '123456',
      name: 'Test User',
      email: 'test@example.com'
    };
    return done(null, mockUser);
  }
  processUserProfile(profile, done);
}));