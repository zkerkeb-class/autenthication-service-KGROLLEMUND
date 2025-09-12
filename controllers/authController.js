const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
const dotenv = require('dotenv');
dotenv.config();
// Configuration des URLs de services
const DB_SERVICE_URL = process.env.DB_SERVICE_URL;
const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const SALT_ROUNDS = 10;

/**
 * Inscription d'un nouvel utilisateur
 */
exports.register = async (req, res) => {
  try {
    console.log('🔄 Début de l\'inscription d\'un nouvel utilisateur');
    
    const { name, email, password, sector, specialties, yearsOfExperience } = req.body;

    if (!name || !email || !password) {
      console.log('❌ Validation échouée: champs manquants');
      return res.status(400).json({ message: 'Tous les champs sont requis' });
    }

    // Vérifier si l'utilisateur existe déjà (en tenant compte des comptes OAuth)
    try {
      const userCheckUrl = `${DB_SERVICE_URL}/api/users/email/${email}`;
      const userCheckResponse = await axios.get(userCheckUrl);
      
      // Si un ou plusieurs utilisateurs sont trouvés
      if (userCheckResponse.data) {
        // Si c'est un tableau d'utilisateurs
        if (Array.isArray(userCheckResponse.data)) {
          
          // Vérifier s'il existe un compte classique (sans OAuth)
          const classicAccount = userCheckResponse.data.find(u => !u.oauthProvider);
          
          if (classicAccount) {
            console.log('❌ Un compte classique existe déjà avec cet email');
            return res.status(409).json({ message: 'Cet email est déjà utilisé avec un compte standard' });
          }
          
          // Vérifier s'il existe un compte OAuth
          const oauthAccount = userCheckResponse.data.find(u => u.oauthProvider);
          
          if (oauthAccount) {
            console.log(`❌ Un compte OAuth existe déjà avec cet email`);
            return res.status(409).json({ 
              message: `Cet email est déjà utilisé avec un compte ${oauthAccount.oauthProvider}. Essayez de vous connecter avec ce fournisseur.` 
            });
          }
        } 
        // Si c'est un objet unique (pour compatibilité avec l'ancienne API)
        else {
          const existingUser = userCheckResponse.data;
          
          // Si c'est un compte standard (non OAuth) ou un compte OAuth avec le même email
          if (!existingUser.oauthProvider) {
            console.log('❌ Un compte classique existe déjà avec cet email');
            return res.status(409).json({ message: 'Cet email est déjà utilisé avec un compte standard' });
          } else {
            console.log(`❌ Un compte OAuth (${existingUser.oauthProvider}) existe déjà avec cet email`);
            return res.status(409).json({ 
              message: `Cet email est déjà utilisé avec un compte ${existingUser.oauthProvider}. Essayez de vous connecter avec ce fournisseur.` 
            });
          }
        }
      }
    } catch (error) {
      // Si l'erreur est 404, l'utilisateur n'existe pas - c'est normal
      if (error.response && error.response.status === 404) {
        console.log('✅ Aucun utilisateur existant trouvé avec cet email, inscription possible');
      } else if (error.response) {
        console.error('❌ Erreur lors de la vérification de l\'utilisateur:', error.response.status, error.response.data);
        return res.status(500).json({ message: 'Erreur serveur lors de la vérification de l\'utilisateur' });
      } else {
        console.error('❌ Erreur lors de la vérification de l\'utilisateur:', error.message);
        return res.status(500).json({ message: 'Erreur serveur lors de la vérification de l\'utilisateur' });
      }
    }

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    // Générer un token de vérification d'email
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Créer l'utilisateur
    const userData = {
      name,
      email,
      password: hashedPassword,
      isAdmin: false,
      isSubscribed: false,
      verificationToken,
      isVerified: false,
      sector: sector || null
    };
    

    // Enregistrer l'utilisateur en BDD
    try {
      const createUserUrl = `${DB_SERVICE_URL}/api/users`;
      
      const createUserResponse = await axios.post(createUserUrl, userData);
      
      const newUser = createUserResponse.data;
      
      // Si des données de profil professionnel sont fournies, créer le profil
      if (sector && specialties && yearsOfExperience) {
        try {
          console.log('Création du profil professionnel...');
          const profileData = {
            userId: newUser.id,
            sector: sector,
            specialties: specialties,
            yearsOfExperience: parseInt(yearsOfExperience) || 0,
            skills: []
          };
          
          await axios.post(`${DB_SERVICE_URL}/api/professional-profiles`, profileData);
        } catch (profileError) {
          console.error('❌ Erreur lors de la création du profil professionnel:', profileError.response?.data || profileError.message);
          // On continue même si la création du profil échoue
        }
      }
      
      // Générer le token JWT
      const token = jwt.sign(
        { userId: newUser.id, email: newUser.email },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      console.log('Token JWT généré avec succès');

      // Envoyer l'email de vérification
      try {
        console.log('Tentative d\'envoi de l\'email de vérification...');
        await axios.post(`${NOTIFICATION_SERVICE_URL}/email-verification`, {
          to: email,
          name: name,
          verificationToken: verificationToken,
          verificationUrl: `${process.env.CLIENT_URL || 'http://localhost:3000'}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`
        });
        console.log(`✅ Email de vérification envoyé`);
      } catch (notifError) {
        console.error('❌ Erreur lors de l\'envoi de l\'email de vérification:', notifError.response?.data || notifError.message);
        // On continue même si l'envoi échoue
      }

      // Retourner la réponse avec le token
      res.status(201).json({
        message: 'Utilisateur créé avec succès',
        token,
        user: {
          id: newUser.id,
          name: newUser.name,
          email: newUser.email,
          isAdmin: newUser.isAdmin,
          isVerified: newUser.isVerified,
          sector: newUser.sector
        }
      });
    } catch (error) {
      console.error('❌ Erreur lors de la création de l\'utilisateur:', error.response?.data || error.message);
      return res.status(500).json({ message: 'Erreur serveur lors de la création de l\'utilisateur' });
    }
  } catch (error) {
    console.error('❌ Erreur non gérée lors de l\'inscription:', error);
    res.status(500).json({ message: 'Erreur serveur lors de l\'inscription' });
  }
};

/**
 * Connexion d'un utilisateur
 */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email et mot de passe requis' });
    }

    // Récupérer l'utilisateur par email
    let user;
    try {
      const userResponse = await axios.get(`${DB_SERVICE_URL}/api/users/email/${email}`, {
        headers: {
          'X-Service': 'auth-service',
          'Origin': 'http://localhost:3001'
        }
      });
      user = userResponse.data;
    } catch (error) {
      if (error.response && error.response.status === 404) {
        console.log('❌ Email ou mot de passe incorrect', error.response);
        return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
      }
      throw error;
    }

    // Vérifier si c'est un compte OAuth (qui ne peut pas se connecter avec mot de passe)
    if (user.oauthProvider) {
      return res.status(400).json({ 
        message: `Ce compte utilise l'authentification via ${user.oauthProvider}. Veuillez vous connecter avec ce service.` 
      });
    }
    
    // Vérifier si le mot de passe existe dans l'objet utilisateur
    if (!user.password) {
      console.error('❌ Mot de passe manquant dans les données utilisateur');
      return res.status(401).json({ message: 'Compte invalide. Veuillez contacter le support.' });
    }

    // Vérifier le mot de passe
    try {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
      }
    } catch (bcryptError) {
      console.error('❌ Erreur bcrypt lors de la vérification du mot de passe:', bcryptError);
      return res.status(500).json({ message: 'Erreur lors de la vérification du mot de passe' });
    }

    // Vérifier si l'email est vérifié
    if (user.verificationToken && !user.isVerified) {
      return res.status(403).json({ 
        message: 'Veuillez vérifier votre adresse email avant de vous connecter',
        needsVerification: true,
        email: user.email
      });
    }

    // Générer le token JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Supprimer le mot de passe de la réponse
    const { password: _, ...userWithoutPassword } = user;

    res.json({ 
      message: 'Connexion réussie',
      token,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({ message: 'Erreur serveur lors de la connexion' });
  }
};

/**
 * Vérifie la validité d'un token JWT.
 * C'est cette fonction que le front-end appelle pour valider une session.
 */
exports.verify = async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Aucun token fourni' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.userId;

        if (!userId) {
            return res.status(401).json({ success: false, message: 'Token invalide : ID utilisateur manquant' });
        }

        // Récupérer les informations à jour de l'utilisateur depuis la base de données
        const userResponse = await axios.get(`${DB_SERVICE_URL}/api/users/${userId}`);
        const user = userResponse.data;

        if (!user) {
            return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
        }
        
        // Le front-end s'attend à recevoir les données utilisateur sous `data.user`
        res.status(200).json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                isAdmin: user.isAdmin,
                isVerified: user.isVerified,
                isSubscribed: user.isSubscribed,
                subscriptionEndDate: user.subscriptionEndDate,
                isProfileCompleted: user.isProfileCompleted,
                sector: user.sector,
            }
        });
    } catch (error) {
        if (error.isAxiosError && error.response?.status === 404) {
            return res.status(404).json({ success: false, message: 'Utilisateur associé au token non trouvé' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, message: 'Token invalide' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: 'Token expiré' });
        }
        console.error('Erreur lors de la vérification du token:', error);
        res.status(500).json({ success: false, message: 'Erreur interne du serveur' });
    }
};

/**
 * Vérification de l'email de l'utilisateur
 */
exports.verifyEmail = async (req, res) => {
  try {
    const { token, email } = req.body;

    if (!token || !email) {
      console.log('❌ Token ou email manquant');
      return res.status(400).json({ message: 'Token et email requis' });
    }

    // Vérifier si l'utilisateur existe
    let user;
    try {
      const userResponse = await axios.get(`${DB_SERVICE_URL}/api/users/email/${email}`, {
        headers: {
          'X-Service': 'auth-service',
          'Origin': 'http://localhost:3001'
        }
      });
      user = userResponse.data;
      
      // Si l'utilisateur est un tableau (plusieurs utilisateurs avec le même email)
      if (Array.isArray(user)) {
        console.log(`⚠️ Plusieurs utilisateurs trouvés avec l'email`);
        // Rechercher un utilisateur avec le token de vérification correspondant
        const matchingUser = user.find(u => u.verificationToken === token);
        
        if (!matchingUser) {
          console.log('❌ Aucun utilisateur trouvé avec ce token de vérification');
          return res.status(400).json({ message: 'Token de vérification invalide' });
        }
        
        user = matchingUser;
        console.log('✅ Utilisateur correspondant trouvé:');
      }
    } catch (error) {
      console.error('❌ Erreur lors de la recherche de l\'utilisateur:', error.response?.data || error.message);
      if (error.response && error.response.status === 404) {
        return res.status(404).json({ message: 'Utilisateur non trouvé' });
      }
      throw error;
    }

    // Vérifier si le token correspond
    
    if (user.verificationToken !== token) {
      console.log('❌ Token de vérification invalide');
      return res.status(400).json({ message: 'Token de vérification invalide' });
    }

    // Mettre à jour l'utilisateur
    await axios.put(`${DB_SERVICE_URL}/api/users/${user.id}`, {
      isVerified: true,
      verificationToken: null
    });
    console.log('✅ Email vérifié avec succès');

    // Envoyer une notification de bienvenue
    try {
      console.log(`📧 Envoi de l'email de bienvenue`);
      await axios.post(`${NOTIFICATION_SERVICE_URL}/welcome`, {
        to: email,
        name: user.name
      });
    } catch (notifError) {
      console.error('❌ Erreur lors de l\'envoi de l\'email de bienvenue:', notifError.response?.data || notifError.message);
      // On continue même si l'envoi échoue
    }

    // Générer un token JWT pour l'authentification automatique
    console.log('🔑 Génération du token JWT pour authentification automatique');
    const jwtToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    console.log('✅ Token JWT généré avec succès');

    // Retourner le token avec la réponse
    res.json({ 
      message: 'Email vérifié avec succès',
      token: jwtToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isProfileCompleted: user.isProfileCompleted || false,
        isAdmin: user.isAdmin || false,
        sector: user.sector || null
      }
    });
    
  } catch (error) {
    console.error('❌ Erreur lors de la vérification de l\'email:', error.response?.data || error.message);
    res.status(500).json({ message: 'Erreur lors de la vérification de l\'email' });
  }
};

/**
 * Déconnexion d'un utilisateur
 */
exports.logout = async (req, res) => {
  try {
    console.log('🔄 Début du processus de déconnexion');
    
    // Récupérer le token depuis l'en-tête d'autorisation
    const authHeader = req.headers.authorization;
    let provider = '';
    let token = '';
    
    // Récupérer le provider depuis le corps de la requête
    if (req.body && req.body.provider) {
      provider = req.body.provider;
    }
    
    // Essayer d'extraire les informations du token
    let userId = null;
    
    if (authHeader) {
      token = authHeader.split(' ')[1];
      
      if (token) {
        
        // Tenter d'extraire le userId et le provider du token
        try {
          const tokenParts = token.split('.');
          if (tokenParts.length === 3) {
            const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
            
            // Extraire le userId et le provider
            userId = payload.userId;
            provider = payload.provider || payload.oauthProvider || '';
 
          }
        } catch (e) {
          console.error('❌ Erreur lors du décodage du token:', e);
        }
        
        // Si on a le userId mais pas le provider, essayer de le récupérer depuis la base de données
        if (userId && !provider) {
          try {
            const userResponse = await axios.get(`${process.env.DB_SERVICE_URL || 'http://localhost:3004'}/api/users/${userId}`);
            if (userResponse.data && userResponse.data.oauthProvider) {
              provider = userResponse.data.oauthProvider;
              console.log(`🔶 Provider trouvé dans la base de données`);
            } else {
              console.log('⚠️ Utilisateur trouvé mais sans provider OAuth');
            }
          } catch (dbError) {
            console.error('❌ Erreur lors de la récupération de l\'utilisateur:', dbError.message);
          }
        }

      }
    } else {
      console.log('⚠️ Aucun token fourni dans l\'en-tête Authorization');
    }
    
    // IMPORTANT: Ne pas utiliser req.logout() ni req.session.destroy() car cela cause un crash
    // avec la configuration actuelle de session
    console.log('⚠️ Déconnexion gérée uniquement côté client pour éviter les erreurs de session');
    
    // Ajouter des instructions spécifiques au fournisseur
    let logoutInstructions = {};
    if (provider) {
      console.log(`🔶 Configuration de la déconnexion pour le provider`);
      
      switch (provider.toLowerCase()) {
        case 'google':
          logoutInstructions = {
            redirectUrl: 'https://accounts.google.com/Logout?continue=https://appengine.google.com/_ah/logout',
            needsRedirect: true
          };
          break;
        case 'github':
          logoutInstructions = {
            redirectUrl: 'https://github.com/logout', 
            needsRedirect: false,
            additionalCleanup: true
          };
          break;
        case 'linkedin':
          logoutInstructions = {
            redirectUrl: 'https://www.linkedin.com/oauth/v2/logout',
            needsRedirect: false,
            additionalCleanup: true
          };
          break;
        default:
          console.log(`⚠️ Provider non reconnu`);
          break;
      }
    } else {
      console.log('⚠️ Aucun provider identifié, déconnexion standard');
    }
    
    const response = { 
      success: true, 
      message: 'Déconnexion réussie',
      instructions: 'Veuillez supprimer le token JWT côté client',
      provider, // Inclure le provider dans la réponse
      logoutInstructions
    };
    
    res.json(response);
  } catch (error) {
    console.error('❌ Erreur lors de la déconnexion:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur lors de la déconnexion',
      error: error.message
    });
  }
};
