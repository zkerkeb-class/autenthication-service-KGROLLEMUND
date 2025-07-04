const passport = require('passport');
const { generateToken } = require('./authMiddleware');
const dotenv = require('dotenv');
dotenv.config();

// Callback pour l'authentification Google
const googleCallback = (req, res) => {
  console.log('Authentification Google réussie, utilisateur:', req.user);
  handleOAuthCallback(req, res);
};

// Callback pour l'authentification GitHub
const githubCallback = (req, res) => {
  console.log('Authentification GitHub réussie, utilisateur:', req.user);
  handleOAuthCallback(req, res);
};

// Callback pour l'authentification LinkedIn
const linkedinCallback = (req, res, next) => {
  passport.authenticate('linkedin', { session: false }, function(err, user, info) {
    console.log('Authenticate callback LinkedIn:', { error: err ? true : false, user: !!user, info });
    
    if (err) {
      console.error('LinkedIn authentication error:', err);
      return res.redirect(`${process.env.CLIENT_URL}?error=auth_failed&message=${encodeURIComponent(err.message || 'Erreur d\'authentification')}`);
    }
    
    if (!user) {
      console.error('LinkedIn authentication failed, no user returned', info);
      return res.redirect(`${process.env.CLIENT_URL}?error=auth_failed&message=${encodeURIComponent(info?.message || 'Authentification échouée')}`);
    }
    
    req.login(user, { session: false }, function(err) {
      if (err) {
        console.error('Error during login:', err);
        return res.redirect(`${process.env.CLIENT_URL}?error=auth_failed&message=${encodeURIComponent('Erreur de connexion')}`);
      }
      
      handleOAuthCallback(req, res);
    });
  })(req, res, next);
};

// Fonction utilitaire pour gérer les callbacks OAuth
const handleOAuthCallback = (req, res) => {
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
  res.redirect(`${process.env.CLIENT_URL}/oauth-callback?token=${token}&userData=${userData}`);
};

module.exports = {
  googleCallback,
  githubCallback,
  linkedinCallback
}; 