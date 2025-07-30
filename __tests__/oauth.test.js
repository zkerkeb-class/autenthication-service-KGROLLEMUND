const { googleCallback } = require('../controllers/oauthController');
const { generateToken } = require('../controllers/authMiddleware');

// Définir la variable d'environnement pour le test
process.env.CLIENT_URL = 'http://localhost:3000';

// Mock du middleware de génération de token
jest.mock('../controllers/authMiddleware', () => ({
  generateToken: jest.fn(),
}));

describe('OAuth Controller', () => {

  beforeEach(() => {
    generateToken.mockClear();
  });

  it('should generate a success page with token and redirect to dashboard if profile is complete', () => {
    const mockUser = {
      id: 'user-123',
      isProfileCompleted: true,
    };
    const mockToken = 'fake-oauth-token';
    generateToken.mockReturnValue(mockToken);

    const req = { user: mockUser };
    const res = {
      send: jest.fn(),
    };

    googleCallback(req, res);

    expect(res.send).toHaveBeenCalledTimes(1);
    const htmlResponse = res.send.mock.calls[0][0];

    // Vérifier que le token est dans la page
    expect(htmlResponse).toContain(`localStorage.setItem('token', '${mockToken}')`);
    // Vérifier que la redirection se fait vers la racine (dashboard)
    expect(htmlResponse).toContain(`const targetUrl = true ? \`\${'http://localhost:3000'}/\` : \`\${'http://localhost:3000'}/complete-profile\`;`);
  });

  it('should generate a success page with token and redirect to complete-profile if profile is incomplete', () => {
    const mockUser = {
      id: 'user-456',
      isProfileCompleted: false,
    };
    const mockToken = 'another-fake-oauth-token';
    generateToken.mockReturnValue(mockToken);

    const req = { user: mockUser };
    const res = {
      send: jest.fn(),
    };

    googleCallback(req, res);

    expect(res.send).toHaveBeenCalledTimes(1);
    const htmlResponse = res.send.mock.calls[0][0];

    expect(htmlResponse).toContain(`localStorage.setItem('token', '${mockToken}')`);
    // Vérifier que la redirection se fait vers la page pour compléter le profil
    expect(htmlResponse).toContain(`const targetUrl = false ? \`\${'http://localhost:3000'}/\` : \`\${'http://localhost:3000'}/complete-profile\`;`);
  });
}); 