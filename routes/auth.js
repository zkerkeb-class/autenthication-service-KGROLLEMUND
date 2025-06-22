const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const authController = require('../controllers/authController');

const router = express.Router();
const DB_SERVICE_URL = process.env.DB_SERVICE_URL || 'http://localhost:3004';
const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:3006/notifications';
console.log('JWT_SECRE here3:', process.env.JWT_SECRET);

// Middleware pour vérifier le JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  console.log('Headers reçus:', req.headers);
  console.log('Auth header:', authHeader);
  
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    console.log('Token extrait:', token);
    
    if (!token) {
      console.error('Format du token invalide');
      return res.status(401).json({ message: 'Format du token invalide' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
      if (err) {
        console.error('Erreur de vérification JWT:', err);
        return res.status(403).json({ message: 'Token invalide ou expiré', error: err.message });
      }
      
      if (!user || !user.userId) {
        console.error('Token invalide: userId manquant');
        return res.status(403).json({ message: 'Token invalide: userId manquant' });
      }
      
      console.log('Token vérifié, utilisateur décodé:', user);
      req.user = user;
      next();
    });
  } else {
    console.error('Pas d\'en-tête d\'autorisation');
    res.status(401).json({ message: 'Authentification requise' });
  }
};

// Générer un JWT
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
router.get('/verify', authenticateJWT, async (req, res) => {
  try {
    console.log('Vérification du token pour userId:', req.user.userId);
    
    if (!req.user.userId) {
      console.error('UserId manquant dans le token');
      return res.status(400).json({ message: 'UserId manquant dans le token' });
    }
    
    // Récupérer les informations de l'utilisateur depuis le service de base de données
    const url = `${DB_SERVICE_URL}/api/users/${req.user.userId}`;
    console.log('Appel API:', url);
    
    const response = await axios.get(url);
    
    if (!response.data) {
      console.error('Utilisateur non trouvé dans la base de données');
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }
    
    console.log('Utilisateur trouvé here3:', response.data);
    res.json({
      user: response.data
    });
  } catch (error) {
    console.error('Erreur lors de la vérification du token:', error);
    console.error('URL appelée:', `${DB_SERVICE_URL}/api/users/${req.user?.userId}`);
    console.error('Détails de l\'erreur:', error.response?.data || 'Pas de données de réponse');
    console.error('Status:', error.response?.status || 'Pas de status');
    
    if (error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        message: 'Service de base de données inaccessible',
        error: error.message
      });
    }
    
    res.status(error.response?.status || 500).json({
      message: 'Erreur lors de la vérification du token',
      error: error.message,
      details: error.response?.data || {}
    });
  }
});

// Routes OAuth Google
router.get('/google', 
  (req, res, next) => {
    console.log('Tentative d\'authentification Google');
    // Vérifier si la stratégie Google est configurée
    if (!passport._strategies.google) {
      return res.status(500).json({
        message: 'Erreur de configuration',
        error: 'La stratégie d\'authentification Google n\'est pas configurée. Vérifiez vos variables d\'environnement.'
      });
    }
    next();
  },
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback', 
  (req, res, next) => {
    console.log('Callback Google reçu');
    if (!passport._strategies.google) {
      return res.status(500).json({
        message: 'Erreur de configuration',
        error: 'La stratégie d\'authentification Google n\'est pas configurée. Vérifiez vos variables d\'environnement.'
      });
    }
    next();
  },
  passport.authenticate('google', { failureRedirect: '/login' }),
  async (req, res) => {
    console.log('Authentification Google réussie, utilisateur:', req.user);
    // Générer un JWT
    const token = generateToken(req.user);
    
    // Encoder les données utilisateur pour les inclure dans l'URL
    const userData = encodeURIComponent(JSON.stringify({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      isProfileCompleted: req.user.isProfileCompleted || false,
      sector: req.user.sector || null
    }));
    
    // Rediriger vers le front-end avec le token et les données utilisateur
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/oauth-callback?token=${token}&userData=${userData}`);
  }
);

// Routes OAuth LinkedIn
router.get('/linkedin', 
  (req, res, next) => {
    console.log('Tentative d\'authentification LinkedIn');
    console.log('Paramètres URL:', req.query);
    console.log('Headers:', req.headers);
    
    if (!passport._strategies.linkedin) {
      return res.status(500).json({
        message: 'Erreur de configuration',
        error: 'La stratégie d\'authentification LinkedIn n\'est pas configurée. Vérifiez vos variables d\'environnement.'
      });
    }
    next();
  },
  (req, res, next) => {
    try {
      console.log('Redirection vers LinkedIn OAuth...');
      // Utiliser la gestion automatique de l'état
      passport.authenticate('linkedin', {
        scope: ['openid', 'profile', 'email'],
        session: false
        // Supprimer "state: SOME_STATE" pour laisser Passport gérer automatiquement
      })(req, res, next);
    } catch (error) {
      console.error('Erreur lors de l\'authentification LinkedIn:', error);
      return res.status(500).json({
        message: 'Erreur lors de l\'authentification LinkedIn',
        error: error.message,
        stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
      });
    }
  }
);

router.get('/linkedin/callback', 
  (req, res, next) => {
    console.log('Callback LinkedIn reçu avec params:', req.query);
    console.log('Callback LinkedIn URL complète:', req.originalUrl);
    
    if (req.query.error) {
      console.error('Erreur retournée par LinkedIn:', req.query.error);
      console.error('Description:', req.query.error_description);
      // Rediriger vers le frontend avec un message d'erreur
      return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed&message=${req.query.error_description || 'Erreur d\'authentification'}`);
    }
    
    if (!passport._strategies.linkedin) {
      return res.status(500).json({
        message: 'Erreur de configuration',
        error: 'La stratégie d\'authentification LinkedIn n\'est pas configurée. Vérifiez vos variables d\'environnement.'
      });
    }
    next();
  },
  (req, res, next) => {
    // Use a custom callback to handle errors explicitly
    passport.authenticate('linkedin', { session: false }, function(err, user, info) {
      console.log('Authenticate callback LinkedIn:', { error: err ? true : false, user: !!user, info });
      
      if (err) {
        console.error('LinkedIn authentication error:', err);
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed&message=${encodeURIComponent(err.message || 'Erreur d\'authentification')}`);
      }
      
      if (!user) {
        console.error('LinkedIn authentication failed, no user returned', info);
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed&message=${encodeURIComponent(info?.message || 'Authentification échouée')}`);
      }
      
      req.login(user, { session: false }, function(err) {
        if (err) {
          console.error('Error during login:', err);
          return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?error=auth_failed&message=${encodeURIComponent('Erreur de connexion')}`);
        }
        
        // Générer un JWT
        const token = generateToken(user);
        
        // Encoder les données utilisateur pour les inclure dans l'URL
        const userData = encodeURIComponent(JSON.stringify({
          id: user.id,
          name: user.name,
          email: user.email,
          isProfileCompleted: user.isProfileCompleted || false,
          sector: user.sector || null
        }));
        
        // Rediriger vers le front-end avec le token et les données utilisateur
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/oauth-callback?token=${token}&userData=${userData}`);
      });
    })(req, res, next);
  }
);

// Routes OAuth GitHub
router.get('/github', 
  (req, res, next) => {
    console.log('Tentative d\'authentification GitHub');
    if (!passport._strategies.github) {
      return res.status(500).json({
        message: 'Erreur de configuration',
        error: 'La stratégie d\'authentification GitHub n\'est pas configurée. Vérifiez vos variables d\'environnement.'
      });
    }
    next();
  },
  passport.authenticate('github', { scope: ['user:email'] })
);

router.get('/github/callback', 
  (req, res, next) => {
    console.log('Callback GitHub reçu');
    if (!passport._strategies.github) {
      return res.status(500).json({
        message: 'Erreur de configuration',
        error: 'La stratégie d\'authentification GitHub n\'est pas configurée. Vérifiez vos variables d\'environnement.'
      });
    }
    next();
  },
  passport.authenticate('github', { failureRedirect: '/login' }),
  async (req, res) => {
    console.log('Authentification GitHub réussie, utilisateur:', req.user);
    // Générer un JWT
    const token = generateToken(req.user);
    
    // Encoder les données utilisateur pour les inclure dans l'URL
    const userData = encodeURIComponent(JSON.stringify({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      isProfileCompleted: req.user.isProfileCompleted || false,
      sector: req.user.sector || null
    }));
    
    // Rediriger vers le front-end avec le token et les données utilisateur
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/oauth-callback?token=${token}&userData=${userData}`);
  }
);

// Déconnexion
router.post('/logout', authController.logout);

// Debugging route for token verification
router.get('/debug-verify', (req, res) => {
  const authHeader = req.headers.authorization;
  
  console.log('Debug: Headers reçus:', req.headers);
  
  if (!authHeader) {
    return res.status(401).json({ 
      message: 'Authentification requise', 
      debug: 'Pas d\'en-tête d\'autorisation trouvé',
      headers: req.headers
    });
  }
  
  const token = authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      message: 'Format du token invalide',
      authHeader
    });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    res.json({ 
      message: 'Token valide', 
      decoded,
      tokenInfo: {
        expiresAt: new Date(decoded.exp * 1000).toISOString(),
        issuedAt: new Date(decoded.iat * 1000).toISOString()
      }
    });
  } catch (error) {
    res.status(403).json({
      message: 'Token invalide', 
      error: error.message,
      tokenSample: token.substring(0, 10) + '...'
    });
  }
});

// Test de connectivité avec le service de base de données
router.get('/test-db-connection', async (req, res) => {
  try {
    const response = await axios.get(`${DB_SERVICE_URL}/health`);
    res.json({
      message: 'Connexion au service de base de données réussie',
      dbServiceResponse: response.data,
      dbServiceUrl: DB_SERVICE_URL
    });
  } catch (error) {
    res.status(500).json({
      message: 'Échec de la connexion au service de base de données',
      error: error.message,
      dbServiceUrl: DB_SERVICE_URL
    });
  }
});

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

// Route pour réinitialiser le mot de passe avec le code
router.post('/reset-password-with-code', authController.resetPasswordWithCode);

// Routes d'authentification classique
// Inscription
router.post('/register', async (req, res) => {
  try {
    await authController.register(req, res);
  } catch (error) {
    console.error('Erreur non gérée dans la route /register:', error);
    res.status(500).json({ message: 'Erreur serveur lors de l\'inscription', error: error.message });
  }
});

// Connexion
router.post('/login', async (req, res) => {
  try {
    await authController.login(req, res);
  } catch (error) {
    console.error('Erreur non gérée dans la route /login:', error);
    res.status(500).json({ message: 'Erreur serveur lors de la connexion', error: error.message });
  }
});

// Vérification d'email
router.post('/verify-email', async (req, res) => {
  try {
    await authController.verifyEmail(req, res);
  } catch (error) {
    console.error('Erreur non gérée dans la route /verify-email:', error);
    res.status(500).json({ message: 'Erreur serveur lors de la vérification de l\'email', error: error.message });
  }
});

// Routes de réinitialisation de mot de passe
router.post('/request-password-reset', authController.requestPasswordReset);
router.post('/verify-reset-code', authController.verifyResetCode);

module.exports = router; 