const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Servir les fichiers statiques (comme index.html)
app.use(express.static(path.join(__dirname, 'public')));

// Configuration de la connexion MySQL
const pool = mysql.createPool({
  host: 'localhost', // Remplacez par votre hôte
  user: 'root', // Remplacez par votre utilisateur
  password: '0000', // Remplacez par votre mot de passe
  database: 'djendjen', // Remplacez par votre base de données
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
});

// Clé secrète pour JWT
const JWT_SECRET = 'your_jwt_secret'; // Remplacez par une clé sécurisée

// Middleware pour vérifier le token JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Aucun token fourni. Veuillez vous connecter.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalide ou expiré.' });
    req.user = user;
    next();
  });
};

// Vérifier l'état de l'authentification
app.get('/api/check-auth', authenticateToken, (req, res) => {
  res.json({ user: req.user, message: 'Utilisateur authentifié.' });
});

// Connexion d'un utilisateur
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Nom d\'utilisateur et mot de passe requis.' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Utilisateur non trouvé.' });

    // Comparaison en texte brut (non sécurisé, comme demandé)
    if (password !== user.password) {
      return res.status(401).json({ error: 'Mot de passe incorrect.' });
    }

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    console.error('Erreur lors de la connexion:', error);
    res.status(500).json({ error: 'Erreur serveur. Veuillez réessayer plus tard.' });
  }
});

// Enregistrer un nouveau visiteur
app.post('/api/visitors', authenticateToken, async (req, res) => {
  const { full_name, id_number, purpose } = req.body;
  if (!full_name || !id_number || !purpose) {
    return res.status(400).json({ error: 'Tous les champs (nom, numéro d\'identité, motif) sont requis.' });
  }

  const badge_code = uuidv4().slice(0, 8); // Génère un code unique de 8 caractères
  const entry_time = new Date();

  try {
    await pool.query(
      'INSERT INTO visitors (full_name, id_number, purpose, entry_time, badge_code) VALUES (?, ?, ?, ?, ?)',
      [full_name, id_number, purpose, entry_time, badge_code]
    );
    res.status(201).json({ message: 'Visiteur enregistré avec succès.', badge_code });
  } catch (error) {
    console.error('Erreur lors de l\'enregistrement du visiteur:', error);
    res.status(500).json({ error: 'Erreur lors de l\'enregistrement du visiteur.' });
  }
});

// Obtenir tous les visiteurs actifs (pour le tableau de bord)
app.get('/api/visitors', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM visitors WHERE exit_time IS NULL ORDER BY entry_time DESC');
    res.json(rows);
  } catch (error) {
    console.error('Erreur lors de la récupération des visiteurs:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des visiteurs.' });
  }
});

// Rechercher un visiteur
app.get('/api/visitors/search', authenticateToken, async (req, res) => {
  const { query } = req.query;
  if (!query) {
    return res.status(400).json({ error: 'Requête de recherche vide.' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT * FROM visitors WHERE full_name LIKE ? OR id_number LIKE ? OR badge_code LIKE ?',
      [`%${query}%`, `%${query}%`, `%${query}%`]
    );
    res.json(rows);
  } catch (error) {
    console.error('Erreur lors de la recherche:', error);
    res.status(500).json({ error: 'Erreur lors de la recherche des visiteurs.' });
  }
});

// Enregistrer la sortie d'un visiteur
app.put('/api/visitors/:id/exit', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const exit_time = new Date();

  try {
    const [result] = await pool.query('UPDATE visitors SET exit_time = ? WHERE id = ?', [exit_time, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Visiteur non trouvé.' });
    }
    res.json({ message: 'Sortie enregistrée avec succès.' });
  } catch (error) {
    console.error('Erreur lors de l\'enregistrement de la sortie:', error);
    res.status(500).json({ error: 'Erreur lors de l\'enregistrement de la sortie.' });
  }
});

// Démarrer le serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});
