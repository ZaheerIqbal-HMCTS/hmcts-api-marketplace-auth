require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const { pool, initDb } = require('./db');

const app = express();

// Render (and most hosting platforms) sit behind a reverse proxy, which adds
// an X-Forwarded-For header identifying the real client IP. Express needs to
// be told to trust this, otherwise express-rate-limit throws a validation
// error on every request and login/registration silently fail.
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (!JWT_SECRET) {
  console.error(
    'JWT_SECRET is not set. Copy .env.example to .env and set a long random value before starting the server.'
  );
  process.exit(1);
}

// Auth uses a bearer token (sent in the Authorization header, stored by the
// browser in localStorage) rather than a cookie. This is a deliberate choice:
// the front end (GitHub Pages) and this API (Render) live on two completely
// different domains, and modern browsers increasingly block or restrict
// cookies set across different sites ("third-party cookies") even with
// SameSite=None configured correctly. A bearer token sidesteps that
// entirely, since it's sent explicitly by the page's own JavaScript rather
// than relying on the browser to attach a cookie automatically.
const allowedOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:8000';
app.use(
  cors({
    origin: allowedOrigin,
  })
);

// Email is optional - if SMTP isn't configured, access requests are still
// stored in the database, but no email is actually sent (the request just
// gets logged instead). This means the feature degrades gracefully rather
// than crashing if someone hasn't set up SMTP yet.
let mailTransporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_PORT === '465',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  console.log('SMTP configured - access request emails will actually be sent.');
} else {
  console.log(
    'SMTP not configured - access requests will be stored but no email will be sent. ' +
    'Set SMTP_HOST, SMTP_USER, SMTP_PASS (and optionally SMTP_PORT) to enable real emails.'
  );
}

app.use(express.json());

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

function issueToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
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

app.post('/api/requests/access', authLimiter, async (req, res) => {
  try {
    const { fullName, organisation, email, jobTitle, apiName, environment, callVolume, useCase } = req.body || {};

    if (!fullName || !organisation || !email || !apiName || !environment || !useCase) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Enter a valid email address.' });
    }

    const reference = 'AR-' + new Date().getFullYear() + '-' + Math.random().toString(36).slice(2, 8).toUpperCase();

    await pool.query(
      `INSERT INTO access_requests (full_name, organisation, email, job_title, api_name, environment, call_volume, use_case, reference)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [fullName, organisation, email, jobTitle || null, apiName, environment, callVolume || null, useCase, reference]
    );

    if (mailTransporter && process.env.API_OWNER_EMAIL) {
      try {
        await mailTransporter.sendMail({
          from: process.env.SMTP_FROM || process.env.SMTP_USER,
          to: process.env.API_OWNER_EMAIL,
          replyTo: email,
          subject: `[HMCTS API Marketplace] Access request for ${apiName} (${reference})`,
          text:
            `A new API access request has been submitted.\n\n` +
            `Reference: ${reference}\n` +
            `API requested: ${apiName}\n` +
            `Environment: ${environment}\n` +
            `Expected call volume: ${callVolume || 'Not specified'}\n\n` +
            `Requested by: ${fullName}${jobTitle ? ' (' + jobTitle + ')' : ''}\n` +
            `Organisation: ${organisation}\n` +
            `Email: ${email}\n\n` +
            `Use case:\n${useCase}\n`,
        });
      } catch (mailErr) {
        // Don't fail the whole request just because email sending had a problem -
        // the request is already safely stored in the database either way.
        console.error('Failed to send access request email:', mailErr);
      }
    } else {
      console.log(`Access request ${reference} stored (no email sent - SMTP/API_OWNER_EMAIL not fully configured).`);
    }

    res.status(201).json({ reference });
  } catch (err) {
    console.error('Access request error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
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
    const token = issueToken(user);

    res.status(201).json({ user: toPublicUser(user), token });
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

    const token = issueToken(user);

    res.json({ user: toPublicUser(user), token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/logout', (req, res) => {
  // Nothing to do server-side - the token lives in the browser's localStorage,
  // not a cookie, so "logging out" just means the client deletes its copy.
  // This endpoint is kept for compatibility with the front end's existing call.
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
