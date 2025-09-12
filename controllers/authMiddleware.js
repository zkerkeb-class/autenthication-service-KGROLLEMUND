const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

// Middleware pour vérifier le JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    
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
  
  // Préparer les données du payload
  const payload = { 
    userId: user.id 
  };
  
  // Ajouter le provider si disponible
  if (user.oauthProvider) {
    payload.oauthProvider = user.oauthProvider;
  }
  return jwt.sign(
    payload,
    process.env.JWT_SECRET || 'secret',
    { expiresIn: '1d' }
  );
};

// Middleware pour vérifier si la stratégie OAuth est configurée
const checkOAuthStrategy = (strategy) => (req, res, next) => {
    const a = process.env[`${strategy.toUpperCase()}_CLIENT_ID`];
    const b = process.env[`${strategy.toUpperCase()}_CLIENT_SECRET`];
  
    if (a && b) {
      return next();
    }
    console.warn(`WARN: Stratégie OAuth '${strategy}' non configurée (variables d'environnement manquantes)`);
    res.status(501).send(`La stratégie d'authentification ${strategy} n'est pas configurée sur ce serveur.`);
  };

module.exports = {
  authenticateJWT,
  generateToken,
  checkOAuthStrategy
}; 