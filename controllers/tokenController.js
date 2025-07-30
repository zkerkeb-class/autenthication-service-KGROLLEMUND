const axios = require('axios');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const DB_SERVICE_URL = process.env.DB_SERVICE_URL;

// Fonction pour tester la connexion à la base de données
const testDbConnection = async (req, res) => {
    try {
        await axios.get(`${DB_SERVICE_URL}/test-db`);
        res.status(200).send('Connexion au service de base de données réussie depuis le service d\'authentification');
    } catch (error) {
        console.error('Erreur de connexion au service BDD:', error.message);
        res.status(500).send('Erreur lors de la connexion au service de base de données');
    }
};

// Fonction pour vérifier un token
const verifyToken = (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Aucun token fourni' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.status(200).json({
            message: 'Token valide',
            data: {
                user: decoded
            }
        });
    } catch (error) {
        res.status(401).json({ message: 'Token invalide' });
    }
};

module.exports = {
    testDbConnection,
    verifyToken
}; 