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

// Fonction utilitaire pour renvoyer une page de succès qui gère le token côté client
const sendOAuthSuccessPage = (req, res) => {
  const token = generateToken(req.user);
  const user = req.user;
  const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';

  // Renvoyer une page HTML avec un script pour stocker le token et rediriger
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Authentification en cours...</title>
      <script>
        // Fonction pour créer un cookie
        function setCookie(name, value, days) {
          let expires = "";
          if (days) {
            const date = new Date();
            date.setTime(date.getTime() + (days*24*60*60*1000));
            expires = "; expires=" + date.toUTCString();
          }
          document.cookie = name + "=" + (value || "")  + expires + "; path=/; SameSite=Lax";
        }

        try {
          // Stocker le token dans le localStorage
          localStorage.setItem('token', '${token}');

          // Stocker l'état de complétion du profil dans un cookie pour le middleware
          setCookie('isProfileCompleted', '${user.isProfileCompleted ? 'true' : 'false'}', 1);
          setCookie('token', '${token}', 1);


          // Décider de la redirection vers l'URL absolue du client
          const targetUrl = ${user.isProfileCompleted} ? \`\${'${clientUrl}'}/\` : \`\${'${clientUrl}'}/complete-profile\`;
          
          // Rediriger
          window.location.replace(targetUrl);
        } catch (e) {
          console.error("Erreur lors de la configuration de l'authentification:", e);
          // Afficher un message d'erreur si quelque chose ne va pas
          document.body.innerHTML = "Une erreur est survenue. Veuillez réessayer.";
        }
      </script>
    </head>
    <body>
      <p>Finalisation de votre connexion...</p>
    </body>
    </html>
  `);
};

// Fonction utilitaire pour gérer les callbacks OAuth
const handleOAuthCallback = (req, res) => {
  sendOAuthSuccessPage(req, res);
};

module.exports = {
  googleCallback,
  githubCallback,
  linkedinCallback
}; 