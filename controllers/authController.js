const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
const dotenv = require('dotenv');
dotenv.config();
// Configuration des URLs de services
console.log('DB_SERVICE_URL here1:', process.env.DB_SERVICE_URL);
console.log('NOTIFICATION_SERVICE_URL here1:', process.env.NOTIFICATION_SERVICE_URL);
const DB_SERVICE_URL = process.env.DB_SERVICE_URL;
const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const SALT_ROUNDS = 10;
console.log('JWT_SECRET here2:', process.env.JWT_SECRET);

/**
 * Inscription d'un nouvel utilisateur
 */
exports.register = async (req, res) => {
  try {
    console.log('🔄 Début de l\'inscription d\'un nouvel utilisateur');
    console.log('Données reçues:', { ...req.body, password: '***HIDDEN***' });
    
    const { name, email, password, sector, specialties, yearsOfExperience } = req.body;

    if (!name || !email || !password) {
      console.log('❌ Validation échouée: champs manquants');
      return res.status(400).json({ message: 'Tous les champs sont requis' });
    }

    // Vérifier si l'utilisateur existe déjà (en tenant compte des comptes OAuth)
    try {
      const userCheckUrl = `${DB_SERVICE_URL}/api/users/email/${email}`;
      console.log('URL de vérification d\'utilisateur:', userCheckUrl);
      
      const userCheckResponse = await axios.get(userCheckUrl);
      console.log('Réponse de la vérification d\'utilisateur:', userCheckResponse.data);
      
      // Si un ou plusieurs utilisateurs sont trouvés
      if (userCheckResponse.data) {
        // Si c'est un tableau d'utilisateurs
        if (Array.isArray(userCheckResponse.data)) {
          console.log(`${userCheckResponse.data.length} utilisateurs trouvés avec cet email`);
          
          // Vérifier s'il existe un compte classique (sans OAuth)
          const classicAccount = userCheckResponse.data.find(u => !u.oauthProvider);
          
          if (classicAccount) {
            console.log('❌ Un compte classique existe déjà avec cet email');
            return res.status(409).json({ message: 'Cet email est déjà utilisé avec un compte standard' });
          }
          
          // Vérifier s'il existe un compte OAuth
          const oauthAccount = userCheckResponse.data.find(u => u.oauthProvider);
          
          if (oauthAccount) {
            console.log(`❌ Un compte OAuth (${oauthAccount.oauthProvider}) existe déjà avec cet email`);
            return res.status(409).json({ 
              message: `Cet email est déjà utilisé avec un compte ${oauthAccount.oauthProvider}. Essayez de vous connecter avec ce fournisseur.` 
            });
          }
        } 
        // Si c'est un objet unique (pour compatibilité avec l'ancienne API)
        else {
          const existingUser = userCheckResponse.data;
          console.log('Utilisateur existant trouvé:', { ...existingUser, password: existingUser.password ? '***HIDDEN***' : null });
          
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
    console.log('Hachage du mot de passe...');
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    console.log('Mot de passe haché avec succès');
    
    // Générer un token de vérification d'email
    const verificationToken = crypto.randomBytes(32).toString('hex');
    console.log('Token de vérification généré');

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
    
    console.log('Tentative de création de l\'utilisateur avec les données:', { ...userData, password: '***HIDDEN***' });

    // Enregistrer l'utilisateur en BDD
    try {
      const createUserUrl = `${DB_SERVICE_URL}/api/users`;
      console.log('URL de création d\'utilisateur:', createUserUrl);
      
      const createUserResponse = await axios.post(createUserUrl, userData);
      console.log('✅ Utilisateur créé avec succès:', { ...createUserResponse.data, password: createUserResponse.data.password ? '***HIDDEN***' : null });
      
      const newUser = createUserResponse.data;
      
      // Si des données de profil professionnel sont fournies, créer le profil
      if (sector && specialties && yearsOfExperience) {
        try {
          console.log('Tentative de création du profil professionnel...');
          const profileData = {
            userId: newUser.id,
            sector: sector,
            specialties: specialties,
            yearsOfExperience: parseInt(yearsOfExperience) || 0,
            skills: []
          };
          
          await axios.post(`${DB_SERVICE_URL}/api/professional-profiles`, profileData);
          console.log(`✅ Profil professionnel créé pour l'utilisateur ${newUser.id}`);
        } catch (profileError) {
          console.error('❌ Erreur lors de la création du profil professionnel:', profileError.response?.data || profileError.message);
          // On continue même si la création du profil échoue
        }
      }
      
      // Générer le token JWT
      console.log('Génération du token JWT...');
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
        console.log(`✅ Email de vérification envoyé à ${email}`);
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
    console.log('🔄 Tentative de connexion');
    const { email, password } = req.body;
    console.log('req.body:', req.body);
    console.log('email:', email);
    console.log('password:', password ? '***HIDDEN***' : 'MISSING');

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
      console.log('user:', user);
      console.log('Utilisateur trouvé:', { 
        id: user.id, 
        email: user.email, 
        hasPassword: user.password,
        passwordLength: user.password ? user.password.length : 0
      });
    } catch (error) {
      if (error.response && error.response.status === 404) {
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
    console.log('Vérification du mot de passe avec bcrypt...');
    try {
      const isPasswordValid = await bcrypt.compare(password, user.password);
      console.log('Résultat de la vérification:', isPasswordValid);
      
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
    console.log('Connexion réussie, renvoi des données utilisateur sans mot de passe');

    res.json({ 
      message: 'Connexion réussie',
      user: userWithoutPassword,
      token
    });
    
  } catch (error) {
    console.error('❌ Erreur lors de la connexion:', error);
    res.status(500).json({ message: 'Erreur lors de la connexion' });
  }
};

/**
 * Vérification de l'email de l'utilisateur
 */
exports.verifyEmail = async (req, res) => {
  try {
    const { token, email } = req.body;

    console.log('🔍 Tentative de vérification d\'email');
    console.log('Token reçu:', token);
    console.log('Email reçu:', email);

    if (!token || !email) {
      console.log('❌ Token ou email manquant');
      return res.status(400).json({ message: 'Token et email requis' });
    }

    // Vérifier si l'utilisateur existe
    let user;
    try {
      console.log(`🔍 Recherche de l'utilisateur avec l'email: ${email}`);
      const userResponse = await axios.get(`${DB_SERVICE_URL}/api/users/email/${email}`, {
        headers: {
          'X-Service': 'auth-service',
          'Origin': 'http://localhost:3001'
        }
      });
      user = userResponse.data;
      console.log('✅ Utilisateur trouvé:', { ...user, password: user.password ? '***HIDDEN***' : null });
      
      // Si l'utilisateur est un tableau (plusieurs utilisateurs avec le même email)
      if (Array.isArray(user)) {
        console.log(`⚠️ Plusieurs utilisateurs trouvés avec l'email ${email}`);
        // Rechercher un utilisateur avec le token de vérification correspondant
        const matchingUser = user.find(u => u.verificationToken === token);
        
        if (!matchingUser) {
          console.log('❌ Aucun utilisateur trouvé avec ce token de vérification');
          return res.status(400).json({ message: 'Token de vérification invalide' });
        }
        
        user = matchingUser;
        console.log('✅ Utilisateur correspondant trouvé:', { ...user, password: user.password ? '***HIDDEN***' : null });
      }
    } catch (error) {
      console.error('❌ Erreur lors de la recherche de l\'utilisateur:', error.response?.data || error.message);
      if (error.response && error.response.status === 404) {
        return res.status(404).json({ message: 'Utilisateur non trouvé' });
      }
      throw error;
    }

    // Vérifier si le token correspond
    console.log(`🔍 Vérification du token: ${token}`);
    console.log(`Token de l'utilisateur: ${user.verificationToken}`);
    
    if (user.verificationToken !== token) {
      console.log('❌ Token de vérification invalide');
      return res.status(400).json({ message: 'Token de vérification invalide' });
    }

    // Mettre à jour l'utilisateur
    console.log(`🔄 Mise à jour de l'utilisateur ${user.id} pour valider l'email`);
    await axios.put(`${DB_SERVICE_URL}/api/users/${user.id}`, {
      isVerified: true,
      verificationToken: null
    });
    console.log('✅ Email vérifié avec succès');

    // Envoyer une notification de bienvenue
    try {
      console.log(`📧 Envoi de l'email de bienvenue à ${email}`);
      await axios.post(`${NOTIFICATION_SERVICE_URL}/welcome`, {
        to: email,
        name: user.name
      });
      console.log(`✅ Email de bienvenue envoyé à ${email}`);
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
 * Demande de réinitialisation de mot de passe par email
 */
exports.requestPasswordResetByEmail = async (req, res) => {
  try {
    console.log('🔄 Début de la demande de réinitialisation par email');
    const { email } = req.body;

    // Vérifier que l'email est fourni
    if (!email) {
      console.log('❌ Email non fourni');
      return res.status(400).json({ message: 'Email requis' });
    }

    console.log(`🔍 Recherche de l'utilisateur avec l'email: ${email}`);
    
    // Vérifier si l'utilisateur existe
    let user;
    try {
      const userResponse = await axios.get(`${DB_SERVICE_URL}/api/users/email/${email}`, {
        headers: {
          'X-Service': 'auth-service',
          'Origin': 'http://localhost:3001'
        }
      });
      
      // Gérer le cas où la réponse est un tableau ou un objet unique
      if (Array.isArray(userResponse.data)) {
        // Trouver un utilisateur non-OAuth
        user = userResponse.data.find(u => !u.oauthProvider);
        if (!user) {
          // Si tous les utilisateurs sont OAuth
          const oauthUser = userResponse.data[0];
          console.log(`⚠️ Compte OAuth trouvé (${oauthUser.oauthProvider}) pour cet email`);
          return res.status(400).json({ 
            message: `Ce compte utilise l'authentification via ${oauthUser.oauthProvider}. Le mot de passe ne peut pas être réinitialisé.` 
          });
        }
      } else {
        user = userResponse.data;
      }
      
      console.log('✅ Utilisateur trouvé:', { id: user.id, email: user.email });
    } catch (error) {
      // Si l'utilisateur n'existe pas, on renvoie quand même un succès pour éviter la divulgation d'informations
      if (error.response && error.response.status === 404) {
        console.log(`⚠️ Aucun utilisateur trouvé avec l'email: ${email}`);
        return res.json({ message: 'Si cet email existe, un email de réinitialisation a été envoyé' });
      }
      throw error;
    }

    // Vérifier si c'est un compte OAuth (qui ne peut pas réinitialiser son mot de passe)
    if (user.oauthProvider) {
      console.log(`⚠️ Compte OAuth (${user.oauthProvider}) - pas de réinitialisation possible`);
      return res.status(400).json({ 
        message: `Ce compte utilise l'authentification via ${user.oauthProvider}. Le mot de passe ne peut pas être réinitialisé.` 
      });
    }

    // Générer un code court à 6 chiffres pour l'email
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const resetTokenExpiry = new Date(Date.now() + 900000); // 15 minutes

    console.log(`🔑 Code de réinitialisation généré: ${resetCode}`);
    console.log(`⏱️ Expiration: ${resetTokenExpiry}`);

    // Mettre à jour l'utilisateur avec le code de réinitialisation
    await axios.put(`${DB_SERVICE_URL}/api/users/${user.id}`, {
      resetCode,
      resetTokenExpiry: resetTokenExpiry.toISOString()
    });
    console.log('✅ Code de réinitialisation enregistré en base de données');

    // Envoyer l'email avec le code de réinitialisation
    try {
      console.log('Envoi de l\'email de réinitialisation...');
      await axios.post(`${NOTIFICATION_SERVICE_URL}/password-reset-request`, {
        to: email,
        name: user.name,
        resetToken,
        resetTokenExpiry: resetTokenExpiry.toISOString()
      });
      console.log(`✅ Email de réinitialisation envoyé à ${email}`);
    } catch (notifError) {
      console.error('❌ Erreur lors de l\'envoi de l\'email de réinitialisation:', notifError.response?.data || notifError.message);
      // On continue même si l'envoi échoue
    }

    res.json({ 
      message: 'Si cet email existe, un email de réinitialisation a été envoyé'
    });
    
  } catch (error) {
    console.error('❌ Erreur lors de la demande de réinitialisation par email:', error.response?.data || error.message);
    res.status(500).json({ message: 'Erreur lors de la demande de réinitialisation' });
  }
};

/**
 * Vérification du code de réinitialisation
 */
exports.verifyResetCode = async (req, res) => {
  try {
    const { email, resetCode } = req.body;

    // Vérifier que tous les champs requis sont présents
    if (!email || !resetCode) {
      return res.status(400).json({ message: 'Email et code de réinitialisation requis' });
    }

    // Rechercher l'utilisateur
    let user;
    try {
      const userResponse = await axios.get(`${DB_SERVICE_URL}/api/users/email/${email}`, {
        headers: {
          'X-Service': 'auth-service'
        }
      });
      
      // Gérer le cas où la réponse est un tableau ou un objet unique
      if (Array.isArray(userResponse.data)) {
        user = userResponse.data.find(u => !u.oauthProvider);
        if (!user) {
          return res.status(400).json({ message: 'Utilisateur non trouvé ou utilise l\'authentification OAuth' });
        }
      } else {
        user = userResponse.data;
      }
    } catch (error) {
      if (error.response && error.response.status === 404) {
        return res.status(404).json({ message: 'Utilisateur non trouvé' });
      }
      throw error;
    }

    // Vérifier si le code est valide et non expiré
    if (!user.resetCode || user.resetCode !== resetCode) {
      return res.status(400).json({ message: 'Code de réinitialisation invalide' });
    }

    if (!user.resetTokenExpiry || new Date(user.resetTokenExpiry) < new Date()) {
      return res.status(400).json({ message: 'Code de réinitialisation expiré' });
    }

    // Générer un token temporaire pour la réinitialisation du mot de passe
    const tempToken = jwt.sign(
      { userId: user.id, purpose: 'password-reset' },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({
      message: 'Code de réinitialisation valide',
      tempToken,
      userId: user.id
    });
  } catch (error) {
    console.error('Erreur lors de la vérification du code:', error);
    res.status(500).json({ message: 'Erreur lors de la vérification du code' });
  }
};

/**
 * Réinitialisation du mot de passe avec un code
 */
exports.resetPasswordWithCode = async (req, res) => {
  try {
    const { token, userId, password } = req.body;

    // Vérifier que tous les champs requis sont présents
    if (!token || !userId || !password) {
      return res.status(400).json({ message: 'Token, userId et mot de passe requis' });
    }

    // Vérifier le token temporaire
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
      
      if (decoded.purpose !== 'password-reset' || decoded.userId !== userId) {
        return res.status(400).json({ message: 'Token invalide' });
      }
    } catch (jwtError) {
      return res.status(400).json({ message: 'Token invalide ou expiré' });
    }

    // Hasher le nouveau mot de passe
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Mettre à jour le mot de passe et réinitialiser les champs de réinitialisation
    await axios.put(`${DB_SERVICE_URL}/api/users/${userId}`, {
      password: hashedPassword,
      resetCode: null,
      resetTokenExpiry: null
    });

    // Envoyer une notification de confirmation de changement de mot de passe
    try {
      console.log('Envoi de la confirmation de changement de mot de passe...');
      await axios.post(`${NOTIFICATION_SERVICE_URL}/password-reset-success`, {
        to: user.email,
        name: user.name
      });
    } catch (notifError) {
      console.error('❌ Erreur lors de l\'envoi de la notification de confirmation de changement de mot de passe:', notifError.response?.data || notifError.message);
      // On continue même si l'envoi échoue
    }

    res.json({ message: 'Mot de passe réinitialisé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la réinitialisation du mot de passe:', error);
    res.status(500).json({ message: 'Erreur lors de la réinitialisation du mot de passe' });
  }
};

/**
 * Déconnexion d'un utilisateur
 */
exports.logout = async (req, res) => {
  try {
    console.log('🔄 Début du processus de déconnexion');
    console.log('Headers reçus:', req.headers);
    console.log('Body reçu:', req.body);
    
    // Récupérer le token depuis l'en-tête d'autorisation
    const authHeader = req.headers.authorization;
    let provider = '';
    let token = '';
    
    // Récupérer le provider depuis le corps de la requête
    if (req.body && req.body.provider) {
      provider = req.body.provider;
      console.log(`🔶 Provider fourni dans la requête: ${provider}`);
    }
    
    // Essayer d'extraire les informations du token
    let userId = null;
    
    if (authHeader) {
      token = authHeader.split(' ')[1];
      
      if (token) {
        console.log('🔑 Token reçu:', token.substring(0, 10) + '...');
        
        // Tenter d'extraire le userId et le provider du token
        try {
          const tokenParts = token.split('.');
          if (tokenParts.length === 3) {
            const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
            console.log('Payload du token:', payload);
            
            // Extraire le userId et le provider
            userId = payload.userId;
            provider = payload.provider || payload.oauthProvider || '';
            console.log(`🔶 Provider extrait du token: ${provider}`);
            console.log(`🔶 UserId extrait du token: ${userId}`);
          }
        } catch (e) {
          console.error('❌ Erreur lors du décodage du token:', e);
        }
        
        // Si on a le userId mais pas le provider, essayer de le récupérer depuis la base de données
        if (userId && !provider) {
          console.log('🔍 Recherche du provider dans la base de données pour userId:', userId);
          try {
            const userResponse = await axios.get(`${process.env.DB_SERVICE_URL || 'http://localhost:3004'}/api/users/${userId}`);
            if (userResponse.data && userResponse.data.oauthProvider) {
              provider = userResponse.data.oauthProvider;
              console.log(`🔶 Provider trouvé dans la base de données: ${provider}`);
            } else {
              console.log('⚠️ Utilisateur trouvé mais sans provider OAuth');
            }
          } catch (dbError) {
            console.error('❌ Erreur lors de la récupération de l\'utilisateur:', dbError.message);
          }
        }
        
        // Dans un système de production, on ajouterait le token à une liste noire
        // ou on le stockerait avec une date d'expiration dans Redis/base de données
        console.log('Token invalidé:', token.substring(0, 10) + '...');
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
      console.log(`🔶 Configuration de la déconnexion pour le provider: ${provider}`);
      
      switch (provider.toLowerCase()) {
        case 'google':
          logoutInstructions = {
            redirectUrl: 'https://accounts.google.com/Logout?continue=https://appengine.google.com/_ah/logout',
            needsRedirect: true
          };
          console.log('Instructions pour Google:', logoutInstructions);
          break;
        case 'github':
          logoutInstructions = {
            redirectUrl: 'https://github.com/logout', 
            needsRedirect: false,
            additionalCleanup: true
          };
          console.log('Instructions pour GitHub:', logoutInstructions);
          break;
        case 'linkedin':
          logoutInstructions = {
            redirectUrl: 'https://www.linkedin.com/oauth/v2/logout',
            needsRedirect: false,
            additionalCleanup: true
          };
          console.log('Instructions pour LinkedIn:', logoutInstructions);
          break;
        default:
          console.log(`⚠️ Provider non reconnu: ${provider}`);
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
    
    console.log('✅ Réponse envoyée:', response);
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