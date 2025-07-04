const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const authController = require('../controllers/authController');
const oauthController = require('../controllers/oauthController');
const tokenController = require('../controllers/tokenController');
const { authenticateJWT, checkOAuthStrategy } = require('../controllers/authMiddleware');
const dotenv = require('dotenv');
dotenv.config();

const router = express.Router();
const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL;
console.log('JWT_SECRE here3:', process.env.JWT_SECRET);

// Initialiser passport dans le routeur pour qu'il soit accessible dans les middlewares
router.use((req, res, next) => {
  req.app.set('passport', passport);
  next();
});

// Middleware pour vérifier le JWT
const generateToken = (user) => {
  console.log('Génération de token pour utilisateur:', user);
  console.log('ID utilisateur:', user.id);
  
  // Préparer les données du payload
  const payload = { 
    userId: user.id 
  };
  
  // Ajouter le provider si disponible
  if (user.oauthProvider) {
    payload.oauthProvider = user.oauthProvider;
    console.log('Provider ajouté au token:', user.oauthProvider);
  }
  
  return jwt.sign(
    payload,
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '1d' }
  );
};

// Vérification du token
router.get('/verify', authenticateJWT, tokenController.verifyToken);

// Routes OAuth Google
router.get('/google', 
  checkOAuthStrategy('Google'),
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback', 
  checkOAuthStrategy('Google'),
  passport.authenticate('google', { failureRedirect: '/login' }),
  oauthController.googleCallback
);

// Routes OAuth LinkedIn
router.get('/linkedin', 
  checkOAuthStrategy('LinkedIn'),
  (req, res, next) => {
    try {
      console.log('Redirection vers LinkedIn OAuth...');
      passport.authenticate('linkedin', {
        scope: ['openid', 'profile', 'email'],
        session: false
      })(req, res, next);
    } catch (error) {
      console.error('Erreur lors de l\'authentification LinkedIn:', error);
      return res.status(500).json({
        message: 'Erreur lors de l\'authentification LinkedIn',
        error: error.message,
      });
    }
  }
);

router.get('/linkedin/callback', 
  checkOAuthStrategy('LinkedIn'),
  oauthController.linkedinCallback
);

// Routes OAuth GitHub
router.get('/github', 
  checkOAuthStrategy('GitHub'),
  passport.authenticate('github', { scope: ['user:email'] })
);

router.get('/github/callback', 
  checkOAuthStrategy('GitHub'),
  passport.authenticate('github', { failureRedirect: '/login' }),
  oauthController.githubCallback
);

// Déconnexion
router.post('/logout', authController.logout);

// Debugging route for token verification
router.get('/debug-verify', tokenController.debugVerifyToken);

// Test de connectivité avec le service de base de données
router.get('/test-db-connection', tokenController.testDbConnection);

// Route pour lister toutes les routes disponibles (debug)
router.get('/', (req, res) => {
  const routes = [];
  
  // Récupérer toutes les routes définies dans ce routeur
  router.stack.forEach(middleware => {
    if (middleware.route) {
      const path = middleware.route.path;
      const methods = Object.keys(middleware.route.methods)
        .filter(method => middleware.route.methods[method]);
      
      routes.push({ path, methods });
    }
  });
  
  res.json({
    message: 'Routes disponibles dans le service d\'authentification',
    routes,
    note: 'Ces routes sont accessibles directement à la racine du service d\'authentification'
  });
});

// Route pour confirmer l'adresse e-mail
router.post('/confirm-email', async (req, res) => {
  try {
    const { email, token } = req.body;
    
    if (!email || !token) {
      return res.status(400).json({ message: 'Email et token sont requis' });
    }
    
    // Vérifier le token de confirmation (à implémenter complètement)
    // Exemple: const validToken = await validateEmailToken(email, token);
    
    // Envoyer un email de confirmation
    try {
      await axios.post(`${NOTIFICATION_SERVICE_URL}/email-confirmation`, {
        to: email,
        confirmationToken: token
      });
      console.log(`Confirmation d'email envoyée à ${email}`);
    } catch (notifError) {
      console.error('Erreur lors de l\'envoi de l\'email de confirmation:', notifError);
      // On continue même si l'envoi d'email échoue
    }
    
    res.json({ 
      success: true, 
      message: 'Email de confirmation envoyé' 
    });
  } catch (error) {
    console.error('Erreur lors de la confirmation d\'email:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erreur lors de la confirmation d\'email', 
      error: error.message 
    });
  }
});

// Route pour demander une réinitialisation de mot de passe
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email requis' });
    }
    
    // Générer un code de réinitialisation (à implémenter complètement)
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    // Exemple: await storeResetCodeInDatabase(email, resetCode);
    
    // Envoyer un email avec le code de réinitialisation
    try {
      await axios.post(`${NOTIFICATION_SERVICE_URL}/password-reset`, {
        to: email,
        resetCode
      });
      console.log(`Code de réinitialisation envoyé à ${email}`);
    } catch (notifError) {
      console.error('Erreur lors de l\'envoi du code de réinitialisation:', notifError);
      return res.status(500).json({ 
        success: false, 
        message: 'Erreur lors de l\'envoi du code de réinitialisation', 
        error: notifError.message 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Si cette adresse email est associée à un compte, un code de réinitialisation a été envoyé.' 
    });
  } catch (error) {
    console.error('Erreur lors de la demande de réinitialisation de mot de passe:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erreur lors de la demande de réinitialisation de mot de passe', 
      error: error.message 
    });
  }
});

// Routes d'authentification classique
// Inscription
router.post('/register', authController.register);

// Connexion
router.post('/login', authController.login);

// Vérification d'email
router.post('/verify-email', authController.verifyEmail);

// Routes de réinitialisation de mot de passe
// Route pour demander une réinitialisation de mot de passe par email
router.post('/request-password-reset-email', authController.requestPasswordResetByEmail);
router.post('/reset-password-with-code', authController.resetPasswordWithCode);

module.exports = router; 