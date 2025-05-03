const OAuth2Strategy = require('passport-oauth2');
const axios = require('axios');
const util = require('util');

/**
 * Stratégie LinkedIn compatible avec OpenID Connect
 * 
 * Cette stratégie permet d'utiliser les nouveaux scopes de LinkedIn (openid, profile, email)
 * tout en restant compatible avec Passport.js
 */
class LinkedInOIDCStrategy extends OAuth2Strategy {
  constructor(options, verify) {
    options = options || {};
    
    // Configuration de base pour OAuth2
    options.authorizationURL = options.authorizationURL || 'https://www.linkedin.com/oauth/v2/authorization';
    options.tokenURL = options.tokenURL || 'https://www.linkedin.com/oauth/v2/accessToken';
    options.scope = options.scope || ['openid', 'profile', 'email'];
    options.scopeSeparator = options.scopeSeparator || ' ';
    
    // Ajout du state si nécessaire
    if (options.state === true) {
      options.state = undefined;
    }
    
    super(options, verify);
    
    this.name = 'linkedin';
    this._profileURL = options.profileURL || 'https://api.linkedin.com/v2/userinfo';
    this._passReqToCallback = options.passReqToCallback;
    
    // Enregistrer les options pour l'utilisation ultérieure
    this._clientID = options.clientID;
    this._clientSecret = options.clientSecret;
    this._callbackURL = options.callbackURL;
  }

  // Récupérer le profil utilisateur
  async userProfile(accessToken, done) {
    try {
      console.log('Récupération du profil LinkedIn avec le token:', accessToken);
      
      const response = await axios.get(this._profileURL, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json'
        }
      });
      
      // Vérifications de base
      if (!response || !response.data) {
        return done(new Error('Failed to fetch user profile'));
      }
      
      console.log('Profil LinkedIn reçu:', JSON.stringify(response.data, null, 2));
      
      // Créer un format de profil compatible avec passport
      const profile = {
        provider: 'linkedin',
        id: response.data.sub,
        displayName: response.data.name,
        name: {
          familyName: response.data.family_name,
          givenName: response.data.given_name
        },
        emails: response.data.email ? [{ value: response.data.email }] : [],
        photos: response.data.picture ? [{ value: response.data.picture }] : [],
        _json: response.data,
        _raw: JSON.stringify(response.data)
      };
      
      done(null, profile);
    } catch (error) {
      console.error('Erreur lors de la récupération du profil LinkedIn:', error);
      console.error('Détails:', error.response?.data || 'No response data');
      
      // Créer un message d'erreur explicite
      const err = new Error(
        `Échec lors de la récupération du profil LinkedIn: ${error.message}`
      );
      err.statusCode = error.response?.status;
      err.data = error.response?.data;
      
      return done(err);
    }
  }
}

// Exporter la stratégie
module.exports = LinkedInOIDCStrategy; 