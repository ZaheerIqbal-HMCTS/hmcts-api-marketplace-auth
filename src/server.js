require('dotenv').config();

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { pool, initDb } = require('./db');

const app = express();

// Render (and most hosting platforms) sit behind a reverse proxy, which adds
// an X-Forwarded-For header identifying the real client IP. Express needs to
// be told to trust this, otherwise express-rate-limit throws a validation
// error on every request and login/registration silently fail.
app.set('trust proxy', 1);

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

const allowedOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:8000';
app.use(
  cors({
    origin: allowedOrigin,
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

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
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: IS_PRODUCTION ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
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

function toPublicUser(row) {
  return {
    id: row.id,
    firstName: row.first_name,
    lastName: row.last_name,
    email: row.email,
    role: row.role,
  };
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/register', authLimiter, async (req, res) => {
  try {
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

    const normalizedEmail = email.toLowerCase();

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with these details could not be created.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (first_name, last_name, email, organisation, role, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, first_name, last_name, email, role`,
      [firstName, lastName, normalizedEmail, organisation || null, role, passwordHash]
    );

    const user = result.rows[0];
    issueSessionCookie(res, user);

    res.status(201).json({ user: toPublicUser(user) });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];

    const passwordHash = user ? user.password_hash : '$2a$12$invalidsaltinvalidsaltinvalidsalte';
    const passwordMatches = await bcrypt.compare(password, passwordHash);

    if (!user || !passwordMatches) {
      return res.status(401).json({ error: 'Incorrect email or password.' });
    }

    issueSessionCookie(res, user);

    res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.sub]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Not signed in.' });

    res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error('/api/me error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`HMCTS API Marketplace auth server listening on http://localhost:${PORT}`);
      console.log(`Accepting requests from: ${allowedOrigin}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialise database:', err);
    process.exit(1);
  });
