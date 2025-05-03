require('dotenv').config();
const axios = require('axios');

// Vérification des variables d'environnement
console.log('=== VÉRIFICATION CONFIGURATION LINKEDIN ===');
console.log('LINKEDIN_CLIENT_ID défini:', !!process.env.LINKEDIN_CLIENT_ID);
console.log('LINKEDIN_CLIENT_SECRET défini:', !!process.env.LINKEDIN_CLIENT_SECRET);

if (!process.env.LINKEDIN_CLIENT_ID || !process.env.LINKEDIN_CLIENT_SECRET) {
  console.error('\n❌ ERREUR: Identifiants LinkedIn manquants!');
  console.log('Créez un fichier .env dans le répertoire courant avec:');
  console.log('LINKEDIN_CLIENT_ID=votre_id_client');
  console.log('LINKEDIN_CLIENT_SECRET=votre_secret_client\n');
  process.exit(1);
}

// Test de connexion à LinkedIn
console.log('\n=== TEST DE L\'API LINKEDIN ===');
console.log('Tentative de connexion à l\'API LinkedIn...');

// URL de base de l'API LinkedIn
const baseURL = 'https://api.linkedin.com/v2';

// Fonction pour tester si les identifiants sont valides
async function testLinkedInAPI() {
  try {
    // Remarque: Impossible de tester complètement sans un token d'accès
    // Ce test vérifie uniquement si l'API répond
    const response = await axios.get('https://api.linkedin.com', {
      timeout: 5000, // 5 secondes timeout
      validateStatus: function (status) {
        return status < 500; // N'échoue pas sur 404 ou autre réponse
      }
    });

    console.log(`API LinkedIn accessible: Status ${response.status}`);
    console.log('✅ API LinkedIn semble accessible\n');
  } catch (error) {
    console.error('❌ ERREUR lors de la connexion à l\'API LinkedIn:');
    console.error(error.message);
    if (error.response) {
      console.error('Statut de la réponse:', error.response.status);
      console.error('Données:', error.response.data);
    }
    console.log('\n');
  }
}

// Tests de configuration
console.log('\n=== VÉRIFICATION DE LA CONFIGURATION ===');
console.log('URL de callback configurée dans le code:');
console.log('http://localhost:3001/api/auth/linkedin/callback');
console.log('\nURL de callback dans le portail LinkedIn:');
console.log('http://localhost:3001/api/auth/linkedin/callback');
console.log('\nVérifiez que ces deux URLs sont EXACTEMENT identiques\n');

console.log('Scopes nécessaires dans le portail LinkedIn:');
console.log('openid, profile, email');
console.log('OU (ancienne API):');
console.log('r_emailaddress, r_liteprofile');
console.log('\nVérifiez que ces scopes sont activés pour votre application\n');

console.log('=== ÉTAPES POUR RÉSOUDRE LES PROBLÈMES ===');
console.log('1. Vérifiez que votre application LinkedIn est approuvée et active');
console.log('2. Assurez-vous que les URLs de redirection sont identiques');
console.log('3. Assurez-vous que les scopes nécessaires sont activés');
console.log('4. Si vous utilisez LinkedIn Developer récemment créé, vérifiez les limitations');
console.log('5. Essayez de recréer les clés d\'API dans le portail LinkedIn\n');

console.log('=== CONTOURNEMENT POSSIBLE ===');
console.log('Si LinkedIn continue à poser problème, envisagez d\'utiliser un autre fournisseur d\'authentification');
console.log('comme Google, GitHub ou Microsoft qui sont généralement plus fiables.\n');

// Exécuter le test
testLinkedInAPI(); 