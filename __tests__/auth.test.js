const request = require('supertest');
const express = require('express');
const router = require('../routes/auth');
const axios = require('axios');
const jwt = require('jsonwebtoken');

// Mock des dépendances externes
jest.mock('axios');
jest.mock('jsonwebtoken');

const app = express();
app.use(express.json());
app.use('/api/auth', router);

describe('Auth Routes - Register', () => {

  beforeEach(() => {
    // Réinitialiser tous les mocks avant chaque test
    axios.get.mockReset();
    axios.post.mockReset();
    jwt.sign.mockReset();
  });

  it('should register a new user successfully', async () => {
    const userData = {
      name: 'John Doe',
      email: 'john.doe@example.com',
      password: 'password123'
    };
    const createdUser = { id: 'user-123', ...userData };
    
    // 1. La vérification de l'utilisateur échoue (404), ce qui est normal
    axios.get.mockRejectedValue({ response: { status: 404 } });
    
    // 2. La création de l'utilisateur réussit
    axios.post.mockResolvedValueOnce({ data: createdUser });
    
    // 3. L'envoi de l'email réussit
    axios.post.mockResolvedValueOnce({ status: 200 });
    
    // 4. La signature du token JWT
    jwt.sign.mockReturnValue('fake-jwt-token');

    const response = await request(app)
      .post('/api/auth/register')
      .send(userData);

    expect(response.status).toBe(201);
    expect(response.body.message).toBe('Utilisateur créé avec succès');
    expect(response.body.token).toBe('fake-jwt-token');
    expect(axios.get).toHaveBeenCalledWith(expect.stringContaining(`/api/users/email/${userData.email}`));
    expect(axios.post).toHaveBeenCalledWith(expect.stringContaining('/api/users'), expect.any(Object));
    expect(axios.post).toHaveBeenCalledWith(expect.stringContaining('/email-verification'), expect.any(Object));
  });

  it('should return 409 if email is already in use by a standard account', async () => {
    const userData = {
        name: 'Jane Doe',
        email: 'jane.doe@example.com',
        password: 'password123'
      };
    
    // La vérification de l'utilisateur réussit et retourne un utilisateur existant sans oauthProvider
    axios.get.mockResolvedValue({ data: { email: userData.email } });

    const response = await request(app)
      .post('/api/auth/register')
      .send(userData);

    expect(response.status).toBe(409);
    expect(response.body.message).toBe('Cet email est déjà utilisé avec un compte standard');
  });

  it('should return 400 if required fields are missing', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({ email: 'test@test.com' }); // Mot de passe et nom manquants

    expect(response.status).toBe(400);
    expect(response.body.message).toBe('Tous les champs sont requis');
  });
});

describe('Auth Routes - Login', () => {

    beforeEach(() => {
      axios.get.mockReset();
      jwt.sign.mockReset();
    });
  
    const loginData = { email: 'john.doe@example.com', password: 'password123' };
    const mockUser = {
      id: 'user-123',
      email: loginData.email,
      password: 'hashedpassword', // Le mot de passe de la BDD est hashé
      isVerified: true,
    };
  
    it('should login successfully with valid credentials', async () => {
      // 1. L'utilisateur est trouvé dans la BDD
      axios.get.mockResolvedValue({ data: mockUser });
      
      // 2. La signature du token JWT
      jwt.sign.mockReturnValue('fake-jwt-token');
      
      // 3. bcrypt.compare est mocké globalement pour ce test
      const bcrypt = require('bcrypt');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);
  
      const response = await request(app)
        .post('/api/auth/login')
        .send(loginData);
  
      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Connexion réussie');
      expect(response.body.token).toBe('fake-jwt-token');
  
      bcrypt.compare.mockRestore(); // Nettoyer le mock
    });
  
    it('should return 401 for incorrect password', async () => {
        axios.get.mockResolvedValue({ data: mockUser });
        
        const bcrypt = require('bcrypt');
        jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);
    
        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);
    
        expect(response.status).toBe(401);
        expect(response.body.message).toBe('Email ou mot de passe incorrect');
    
        bcrypt.compare.mockRestore();
      });
  
      it('should return 401 if user does not exist', async () => {
        axios.get.mockRejectedValue({ response: { status: 404 } });
    
        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);
    
        expect(response.status).toBe(401);
      });

      it('should return 400 if account is an OAuth account', async () => {
        axios.get.mockResolvedValue({ data: { ...mockUser, oauthProvider: 'google' } });
    
        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);
    
        expect(response.status).toBe(400);
        expect(response.body.message).toContain('Ce compte utilise l\'authentification via');
      });

      it('should return 403 if email is not verified', async () => {
        axios.get.mockResolvedValue({ data: { ...mockUser, isVerified: false, verificationToken: 'some-token' } });
        
        // CORRECTION : Il faut que la vérification du mot de passe réussisse pour atteindre la vérification de l'email
        const bcrypt = require('bcrypt');
        jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);

        const response = await request(app)
          .post('/api/auth/login')
          .send(loginData);
    
        expect(response.status).toBe(403);
        expect(response.body.message).toBe('Veuillez vérifier votre adresse email avant de vous connecter');

        bcrypt.compare.mockRestore();
      });
  });

describe('Auth Routes - Verify Token', () => {
    beforeEach(() => {
        axios.get.mockReset();
        jwt.verify.mockReset();
    });

    it('should return user data for a valid token', async () => {
        const token = 'valid-token';
        const decodedToken = { userId: 'user-123' };
        const mockUser = {
            id: 'user-123',
            name: 'Test User',
            email: 'test@test.com',
            isSubscribed: true,
            subscriptionEndDate: new Date().toISOString()
        };

        // 1. jwt.verify réussit et décode le token
        jwt.verify.mockReturnValue(decodedToken);
        // 2. axios.get réussit et retourne les données de l'utilisateur
        axios.get.mockResolvedValue({ data: mockUser });

        const response = await request(app)
            .get('/api/auth/verify')
            .set('Authorization', `Bearer ${token}`);

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        // CORRECTION: La structure de la réponse a été aplatie
        expect(response.body.user).toBeDefined();
        expect(response.body.user.id).toBe(mockUser.id);
        expect(jwt.verify).toHaveBeenCalledWith(token, process.env.JWT_SECRET);
        expect(axios.get).toHaveBeenCalledWith(expect.stringContaining(`/api/users/${decodedToken.userId}`));
    });

    it('should return 401 for an invalid token', async () => {
        const token = 'invalid-token';
        
        // CORRECTION: Simuler une erreur avec le bon nom pour être attrapée par le contrôleur
        const error = new Error('Invalid token');
        error.name = 'JsonWebTokenError';
        jwt.verify.mockImplementation(() => {
            throw error;
        });

        const response = await request(app)
            .get('/api/auth/verify')
            .set('Authorization', `Bearer ${token}`);

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Token invalide');
    });

    it('should return 404 if user from token is not found', async () => {
        const token = 'valid-token-for-deleted-user';
        const decodedToken = { userId: 'user-that-does-not-exist' };

        // jwt.verify réussit
        jwt.verify.mockReturnValue(decodedToken);
        // CORRECTION: Simuler une erreur axios avec les bonnes propriétés
        axios.get.mockRejectedValue({ isAxiosError: true, response: { status: 404 } });

        const response = await request(app)
            .get('/api/auth/verify')
            .set('Authorization', `Bearer ${token}`);
            
        expect(response.status).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Utilisateur associé au token non trouvé');
    });
});

describe('Auth Routes - Email Verification', () => {

    beforeEach(() => {
      axios.get.mockReset();
      axios.post.mockReset();
      axios.put.mockReset();
    });
  
    it('should verify an email with a valid token', async () => {
      const userData = { email: 'test@test.com', token: 'valid-token' };
      const mockUser = { id: 'user-123', verificationToken: 'valid-token', isVerified: false };
      
      // L'utilisateur est trouvé avec le bon token
      axios.get.mockResolvedValue({ data: mockUser });
      // La mise à jour de l'utilisateur réussit
      axios.put.mockResolvedValue({ data: { ...mockUser, isVerified: true, verificationToken: null } });
  
      const response = await request(app)
        .post('/api/auth/verify-email')
        .send(userData);
  
      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Email vérifié avec succès');
      expect(axios.put).toHaveBeenCalledWith(expect.stringContaining(`/api/users/${mockUser.id}`), {
        isVerified: true,
        verificationToken: null,
      });
    });
}); 