const axios = require('axios');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const DB_SERVICE_URL = process.env.DB_SERVICE_URL;

// Vérification du token
const verifyToken = async (req, res) => {
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
    
    console.log('Utilisateur trouvé:', response.data);
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
};

// Debugging route for token verification
const debugVerifyToken = (req, res) => {
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
};

// Test de connectivité avec le service de base de données
const testDbConnection = async (req, res) => {
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
};

module.exports = {
  verifyToken,
  debugVerifyToken,
  testDbConnection
}; 