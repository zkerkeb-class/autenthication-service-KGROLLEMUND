const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const passport = require('passport');
const session = require('express-session');
const authRoutes = require('./routes/auth');
const axios = require('axios');
const promBundle = require('express-prom-bundle');

dotenv.config();

// Charger les variables d'environnement
const envPath = path.resolve(__dirname, '.env');
const envExists = fs.existsSync(envPath);


if (envExists) {
  const result = dotenv.config({ path: envPath });
  if (result.error) {
    console.error("Erreur lors du chargement du fichier .env:", result.error);
  } else {
    console.log("Fichier .env chargé avec succès");
  }
} else {
  console.error("ATTENTION: Le fichier .env n'existe pas.");
}

// Initialiser l'application Express
const app = express();
const PORT = process.env.PORT || 3001;

// Afficher les variables d'environnement importantes (sans les secrets)
console.log('PORT:', PORT);
console.log('CLIENT_URL:', process.env.CLIENT_URL || 'http://localhost:3000');
console.log('AUTH_SERVICE_URL:', process.env.AUTH_SERVICE_URL || 'http://localhost:3001');
console.log('DB_SERVICE_URL:', process.env.DB_SERVICE_URL || 'http://localhost:3004');

// Configurer les middlewares
app.use(cors({
  origin: [process.env.CLIENT_URL || 'http://localhost:3000', 'http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

// Configurer la session
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 heures
  }
});

app.use(sessionMiddleware);

// Initialiser Passport
app.use(passport.initialize());
app.use(passport.session());

// Configurer les stratégies Passport
require('./config/passport');

// Middleware de journalisation pour les requêtes
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Routes principales - Nous utilisons un préfixe unique pour plus de clarté
app.use('/api/auth', authRoutes);

// Route de test pour la santé du service
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Service d\'authentification opérationnel' });
});

// Middleware de gestion des erreurs
app.use((err, req, res, next) => {
  console.error('Erreur non gérée:', err);
  res.status(500).json({ message: 'Erreur interne du serveur', error: err.message });
});

const metricsMiddleware = promBundle({
  includeMethod: true,
  includePath: true,
  includeStatusCode: true,
  includeUp: true,
  customLabels: { project_name: 'authentification-service' }, // Remplacer par le nom du service
  promClient: { collectDefaultMetrics: {} }
});
app.use(metricsMiddleware);

// Route pour exposer les métriques Prometheus
app.get('/metrics', (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.end(promBundle.promClient.register.metrics());
});

// Démarrer le serveur
app.listen(PORT, () => {
  console.log(`Service d'authentification en cours d'exécution sur le port ${PORT}`);
}); 