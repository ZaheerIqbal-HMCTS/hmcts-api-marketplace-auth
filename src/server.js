require('dotenv').config();

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const db = require('./db');

const app = express();

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE_NAME = 'hmcts_marketplace_session';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (!JWT_SECRET) {
  console.error(
    'JWT_SECRET is not set. Copy .env.example to .env and set a long random value before starting the server.'
  );
  process.exit(1);
}

// --- Middleware -----------------------------------------------------------

// Allow the static front end (e.g. your GitHub Pages site) to call this API
// with credentials (cookies). Set FRONTEND_ORIGIN in .env to the exact origin
// your site is served from, e.g. https://zaheeriqbal-hmcts.github.io
const allowedOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:8000';
app.use(
  cors({
    origin: allowedOrigin,
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

// Basic protection against brute-force login/register attempts.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// --- Helpers ---------------------------------------------------------------

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function issueSessionCookie(res, user) {
  const token = jwt.sign(
    { sub: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true, // not readable by client-side JS - protects against XSS token theft
    secure: IS_PRODUCTION, // only sent over HTTPS in production
    sameSite: IS_PRODUCTION ? 'none' : 'lax', // 'none' needed for cross-site (GitHub Pages -> your API host)
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Not signed in.' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

// --- Routes ------------------------------------------------------------

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/register', authLimiter, async (req, res) => {
  const { firstName, lastName, email, organisation, role, password } = req.body || {};

  if (!firstName || !lastName || !email || !role || !password) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (!['consumer', 'producer'].includes(role)) {
    return res.status(400).json({ error: 'Role must be "consumer" or "producer".' });
  }
  if (typeof password !== 'string' || password.length < 12) {
    return res.status(400).json({ error: 'Password must be at least 12 characters long.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) {
    // Deliberately vague to avoid confirming which emails are registered.
    return res.status(409).json({ error: 'An account with these details could not be created.' });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const result = db
    .prepare(
      `INSERT INTO users (first_name, last_name, email, organisation, role, password_hash)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(firstName, lastName, email.toLowerCase(), organisation || null, role, passwordHash);

  const user = { id: result.lastInsertRowid, email: email.toLowerCase(), role };
  issueSessionCookie(res, user);

  res.status(201).json({
    user: { id: user.id, firstName, lastName, email: user.email, role },
  });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());

  // Always run bcrypt.compare even if user is missing, using a dummy hash,
  // so response timing doesn't reveal whether the email exists.
  const passwordHash = user ? user.password_hash : '$2a$12$invalidsaltinvalidsaltinvalidsalte';
  const passwordMatches = await bcrypt.compare(password, passwordHash);

  if (!user || !passwordMatches) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }

  issueSessionCookie(res, user);

  res.json({
    user: {
      id: user.id,
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      role: user.role,
    },
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (!user) return res.status(401).json({ error: 'Not signed in.' });

  res.json({
    user: {
      id: user.id,
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      role: user.role,
    },
  });
});

app.listen(PORT, () => {
  console.log(`HMCTS API Marketplace auth server listening on http://localhost:${PORT}`);
  console.log(`Accepting requests from: ${allowedOrigin}`);
});
