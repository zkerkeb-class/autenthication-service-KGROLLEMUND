const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

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

// Middleware pour vérifier si la stratégie OAuth est configurée
const checkOAuthStrategy = (strategy) => {
  return (req, res, next) => {
    console.log(`Tentative d'authentification ${strategy}`);
    if (!req.app.get('passport')._strategies[strategy.toLowerCase()]) {
      return res.status(500).json({
        message: 'Erreur de configuration',
        error: `La stratégie d'authentification ${strategy} n'est pas configurée. Vérifiez vos variables d'environnement.`
      });
    }
    next();
  };
};

module.exports = {
  authenticateJWT,
  generateToken,
  checkOAuthStrategy
}; 