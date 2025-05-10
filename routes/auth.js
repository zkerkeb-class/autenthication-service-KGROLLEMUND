const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const router = express.Router();
const DB_SERVICE_URL = process.env.DB_SERVICE_URL || 'http://localhost:3004';

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
    
    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
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
  
  return jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET || 'your-secret-key',
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
    const url = `${DB_SERVICE_URL}/users/${req.user.userId}`;
    console.log('Appel API:', url);
    
    const response = await axios.get(url);
    
    if (!response.data) {
      console.error('Utilisateur non trouvé dans la base de données');
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }
    
    console.log('Utilisateur trouvé:', response.data);
    res.json({
      user: response.data
    });
  } catch (error) {
    console.error('Erreur lors de la vérification du token:', error);
    console.error('URL appelée:', `${DB_SERVICE_URL}/users/${req.user?.userId}`);
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
  (req, res) => {
    console.log('Authentification Google réussie, utilisateur:', req.user);
    // Générer un JWT
    const token = generateToken(req.user);
    
    // Rediriger vers le front-end avec le token
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/oauth-callback?token=${token}`);
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
        
        // Rediriger vers le front-end avec le token
        return res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/oauth-callback?token=${token}`);
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
  (req, res) => {
    console.log('Authentification GitHub réussie, utilisateur:', req.user);
    // Générer un JWT
    const token = generateToken(req.user);
    
    // Rediriger vers le front-end avec le token
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/oauth-callback?token=${token}`);
  }
);

// Déconnexion
router.post('/logout', (req, res) => {
  req.logout();
  res.json({ message: 'Déconnexion réussie' });
});

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
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
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

// Route pour tester la configuration
router.get('/test', (req, res) => {
  console.log('Route de test appelée');
  
  // Liste des routes disponibles
  const routes = [];
  router.stack.forEach(middleware => {
    if (middleware.route) {
      const path = middleware.route.path;
      const methods = Object.keys(middleware.route.methods)
        .filter(method => middleware.route.methods[method])
        .join(', ');
      
      routes.push(`${methods.toUpperCase()} ${path}`);
    }
  });

  res.json({
    message: 'Test du service d\'authentification',
    environment: {
      PORT: process.env.PORT || '3001',
      DB_SERVICE_URL: DB_SERVICE_URL,
      CLIENT_URL: process.env.CLIENT_URL || 'http://localhost:3000',
      JWT_SECRET_DEFINED: !!process.env.JWT_SECRET
    },
    routes: routes,
    headers: req.headers,
    testing_info: {
      verify_url: '/verify',
      debug_verify_url: '/debug-verify',
      note: 'Ces endpoints sont directement accessibles à la racine du service'
    }
  });
});

module.exports = router; 