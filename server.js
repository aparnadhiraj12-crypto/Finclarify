// server.js
require('dotenv').config();
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
const express = require('express');
const cors = require('cors');
const path = require('path');
const bodyParser = require('body-parser');
const fetch = require('node-fetch'); // keep if installed; Node 18+ has global fetch
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const pdfParse = require('pdf-parse');

const app = express();
const port = process.env.PORT || 3000;

// ===== Config (from .env) =====
const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || 'Password';
const DB_NAME = process.env.DB_NAME || 'finclarity';

const HACKRX_API_KEY = process.env.HACKRX_API_KEY || 'change_this_in_env';
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'tinyllama:latest';

// ===== MySQL Connection (mysql2/promise) =====
const dbConfig = {
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

let pool;
(async () => {
  try {
    pool = await mysql.createPool(dbConfig);

    // Create database tables if they don't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS webhook_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        endpoint VARCHAR(255) NOT NULL,
        payload TEXT NOT NULL,
        headers TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('✅ MySQL pool created and tables ensured');
  } catch (err) {
    console.error('❌ MySQL pool error (startup):', err);
    process.exit(1);
  }
})();

// ===== Middleware =====
app.use(cors({
  // set this to the URL where your frontend runs (e.g., http://localhost:5173)
  origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173',
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_key_here',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // set true only when using HTTPS in production
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// ===== Helper: log webhook to DB =====
async function saveWebhookLog(endpoint, payload, headers = {}) {
  try {
    const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const headersStr = JSON.stringify(headers);
    await pool.query('INSERT INTO webhook_logs (endpoint, payload, headers) VALUES (?, ?, ?)', [endpoint, payloadStr, headersStr]);
  } catch (err) {
    console.error('❌ Error saving webhook log:', err);
  }
}

// ===== Register =====
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, email]);
    if (rows.length > 0) {
      return res.status(409).json({ success: false, message: 'User or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);

    req.session.user = { username };
    console.log('✅ Session set for:', username);
    res.status(201).json({ success: true, message: 'User registered successfully' });
  } catch (err) {
    console.error('❌ Registration error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ===== Login =====
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: 'Missing credentials' });

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    req.session.user = { username };
    res.json({ success: true, message: 'Login successful' });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// ===== Session Check =====
app.get('/api/session', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// ===== Ollama Chatbot =====
// We'll store conversation history in-memory per server instance. For production, use a DB or per-session storage.
let conversationHistory = [];

async function sendToOllama(messages) {
  // messages: [{role:'user'|'assistant', content: '...'}, ...]
  const payload = {
    model: OLLAMA_MODEL,
    messages,
    stream: false
  };

  const url = `${OLLAMA_URL}/api/chat`;

  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  return resp;
}

app.post('/api/chat', async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ reply: 'No message provided' });

  try {
    conversationHistory.push({ role: 'user', content: message });
    console.log('Sending to Ollama:', conversationHistory);

    const ollamaResp = await sendToOllama(conversationHistory);

    if (!ollamaResp.ok) {
      console.error('Ollama API returned status:', ollamaResp.status);
      const text = await ollamaResp.text().catch(() => '');
      return res.status(500).json({ reply: `Error from AI model server (${ollamaResp.status}): ${text}` });
    }

    const data = await ollamaResp.json();

    const botReply = data?.message?.content || data?.choices?.[0]?.message?.content || 'No response from AI';
    conversationHistory.push({ role: 'assistant', content: botReply });

    return res.json({ reply: botReply });
  } catch (err) {
    console.error('❌ Ollama API error:', err);
    return res.status(500).json({ reply: 'Error connecting to AI model' });
  }
});

// Endpoint to reset conversation (optional)
app.post('/api/chat/reset', (req, res) => {
  conversationHistory = [];
  res.json({ ok: true, message: 'Conversation reset' });
});

// ===== HackRx handler (secure, token-protected) =====
async function handleHackRxLogic(documentsField, questionsArray) {
  // Accept documentsField as either a string URL or array of URLs
  const docUrl = Array.isArray(documentsField) ? documentsField[0] : documentsField;
  if (!docUrl || typeof docUrl !== 'string') {
    throw new Error('Invalid document URL');
  }

  // Fetch the PDF bytes
  const pdfRes = await fetch(docUrl);
  if (!pdfRes.ok) throw new Error(`Unable to fetch PDF: ${pdfRes.status}`);

  const pdfBuffer = Buffer.from(await pdfRes.arrayBuffer());
  const pdfData = await pdfParse(pdfBuffer);
  const pdfText = pdfData && pdfData.text ? pdfData.text : '';

  // Simple answer extraction (naive search). Replace with real NLP/AI when desired.
  const answers = questionsArray.map(q => {
    const qLower = (q || '').toString().toLowerCase();
    if (!qLower) return 'Empty question';
    const firstToken = qLower.split(' ')[0];
    const idx = pdfText.toLowerCase().indexOf(firstToken);
    if (idx !== -1) {
      return pdfText.substring(Math.max(0, idx - 50), idx + 300).trim() + '...';
    } else {
      return 'Answer not found in document';
    }
  });

  return answers;
}

// Single secure endpoint to satisfy HackRx webhook tests
app.post(['/hackrx/run', '/api/v1/hackrx/run'], async (req, res) => {
  try {
    // Auth header check
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid authorization header' });
    }
    const token = authHeader.split(' ')[1];
    if (token !== HACKRX_API_KEY) {
      return res.status(403).json({ error: 'Invalid API key' });
    }

    const { documents, questions } = req.body;
    if (!documents || !questions || !Array.isArray(questions)) {
      return res.status(400).json({ error: 'Invalid request format. Expected { documents, questions[] }' });
    }

    // Log incoming webhook to DB
    await saveWebhookLog(req.path, req.body, req.headers);

    // Process document and questions
    const answers = await handleHackRxLogic(documents, questions);

    return res.json({ answers });
  } catch (err) {
    console.error('❌ Error in HackRx endpoint:', err);
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

// ===== Simple health checks =====
app.get('/health', (req, res) => res.json({ ok: true, version: '1.0.0' }));

app.get('/ollama-status', async (req, res) => {
  // Quick ping to Ollama to check status and available models
  try {
    const r = await fetch(`${OLLAMA_URL}/models`);
    if (!r.ok) {
      const txt = await r.text().catch(() => '');
      return res.status(r.status).json({ ok: false, status: r.status, message: txt });
    }
    const data = await r.json();
    // Check if desired model is present
    const models = Array.isArray(data) ? data : (data.models || []);
    const installed = models.some(m => (m.name || '').toLowerCase().includes(OLLAMA_MODEL.split(':')[0].toLowerCase()));
    return res.json({ ok: true, installed, models });
  } catch (err) {
    console.error('❌ Ollama status check failed:', err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ===== Static routes for your frontend =====
app.get('/', (req, res) => res.sendFile(path.resolve(__dirname, 'public', 'login.html')));
app.get('/create', (req, res) => res.sendFile(path.resolve(__dirname, 'public', 'create.html')));
app.get('/home', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.sendFile(path.resolve(__dirname, 'public', 'home.html'));
});

// ===== Start Server =====
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
  console.log(`🔎 Ollama URL: ${OLLAMA_URL}  |  Model: ${OLLAMA_MODEL}`);
  console.log(`🔐 HackRx API key required: ${HACKRX_API_KEY !== 'change_this_in_env' ? 'yes' : 'no (set HACKRX_API_KEY in .env)'}`);
});
