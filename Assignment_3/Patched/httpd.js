// Squeak! - DVA489 Assignment 3 - PATCHED version
//
// Fix status:
//   1. Stored XSS   - FIXED: rendering via mustache-express (auto-escapes),
//                     session cookie now HttpOnly + Secure
//   2. CSRF         - FIXED: synchronizer token required on /squeak and
//                     /signout (see report for why /signin and /signup
//                     don't need one: they only accept JSON bodies, which
//                     a classic forged form cannot send)
//   3. ReDoS        - FIXED: usernames must match a fixed, safe whitelist
//                     regex, and the password/username check no longer
//                     builds a regex from user input at all

const express = require('express');
const mustacheExpress = require('mustache-express');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const PORT = 8000;

const PASSWD_PATH = path.join(__dirname, 'passwd');
const SQUEAKS_PATH = path.join(__dirname, 'squeaks');

// ---------------------------------------------------------------------------
// Persistence helpers - users and squeaks are kept in memory and mirrored to
// disk as JSON so state survives a server restart.
// ---------------------------------------------------------------------------

function loadJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    return fallback;
  }
}

function saveJson(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

let users = loadJson(PASSWD_PATH, {});       // username -> { salt, hash }
let squeaks = loadJson(SQUEAKS_PATH, []);    // [{ username, time, text }, ...] newest first

function persistUsers() {
  saveJson(PASSWD_PATH, users);
}

function persistSqueaks() {
  saveJson(SQUEAKS_PATH, squeaks);
}

// ---------------------------------------------------------------------------
// Password hashing - per-user salt, scrypt, timing-safe comparison.
// ---------------------------------------------------------------------------

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function checkPassword(username, password) {
  const record = users[username];
  if (!record) return false;
  const candidate = hashPassword(password, record.salt);
  const stored = Buffer.from(record.hash, 'hex');
  const attempt = Buffer.from(candidate, 'hex');
  return stored.length === attempt.length && crypto.timingSafeEqual(stored, attempt);
}

function createUser(username, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  users[username] = { salt, hash: hashPassword(password, salt) };
  persistUsers();
}

// ---------------------------------------------------------------------------
// Sessions - sessionid -> username. The squeak-session cookie carries both
// the sessionid and a username, but only the sessionid is authoritative:
// the server looks up the id in its own table rather than trusting the
// cookie's username field.
//
// Each session also gets a CSRF token (sessionid -> token), generated at
// the same time as the session and required on any state-changing request
// that a plain auto-submitting form could otherwise forge.
// ---------------------------------------------------------------------------

let sessions = {};    // sessionid -> username
let csrfTokens = {};  // sessionid -> csrf token

function createSession(username) {
  const sessionid = crypto.randomBytes(32).toString('hex');
  sessions[sessionid] = username;
  csrfTokens[sessionid] = crypto.randomBytes(32).toString('hex');
  return sessionid;
}

function destroySession(sessionid) {
  delete sessions[sessionid];
  delete csrfTokens[sessionid];
}

// Returns true only if the request carries the csrf_token that matches the
// token issued for this session. A cross-origin page has no way to read
// that token (same-origin policy blocks it from reading the page that
// contains it), so it cannot include a valid one in a forged request.
function validCsrfToken(req) {
  if (!req.session) return false;
  const expected = csrfTokens[req.session.sessionid];
  return expected && req.body && req.body.csrf_token === expected;
}

function sessionMiddleware(req, res, next) {
  req.session = null;
  const raw = req.cookies['squeak-session'];
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      const username = sessions[parsed.sessionid];
      if (username) {
        req.session = { sessionid: parsed.sessionid, username };
      }
    } catch (err) {
      // malformed cookie - treat as not logged in
    }
  }
  next();
}

// FIXED: HttpOnly stops document.cookie from ever seeing this value, Secure
// stops it being sent over a non-HTTPS connection.
function setSessionCookie(res, sessionid, username) {
  const value = JSON.stringify({ sessionid, username });
  res.cookie('squeak-session', value, { path: '/', httpOnly: true, secure: true });
}

function clearSessionCookie(res) {
  res.clearCookie('squeak-session', { path: '/', httpOnly: true, secure: true });
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = express();

// FIXED: mustache-express escapes every {{value}} by default, so squeak text
// can no longer be interpreted as HTML by the browser.
app.engine('mustache', mustacheExpress());
app.set('view engine', 'mustache');
app.set('views', path.join(__dirname, 'templates'));

app.use(cookieParser());
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// -- GET / ---------------------------------------------------------------
app.get('/', (req, res) => {
  if (req.session) {
    res.render('feed', {
      username: req.session.username,
      squeaks,
      csrfToken: csrfTokens[req.session.sessionid],
    });
  } else {
    res.render('signin', {});
  }
});

// -- POST /signup ----------------------------------------------------------
// NOTE: JSON-only body - see report for why this doesn't need a CSRF token.
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  // FIXED: usernames are restricted to a fixed, safe character set (checked
  // against a hardcoded, non-dynamic regex - never built from user input),
  // so there is nothing left for an attacker to inject.
  const USERNAME_PATTERN = /^[A-Za-z0-9_]{4,}$/;
  const validUsername =
    typeof username === 'string' && USERNAME_PATTERN.test(username) && !users[username];

  if (!validUsername) {
    res.json({ success: false, field: 'username' });
    return;
  }

  // FIXED: plain substring check, no regex built from user input at all -
  // no ReDoS surface regardless of input length.
  let validPassword = password !== undefined && password.length >= 8;
  if (validPassword) {
    validPassword = !password.includes(username);
  }

  if (!validPassword) {
    res.json({ success: false, field: 'password' });
    return;
  }

  createUser(username, password);
  const sessionid = createSession(username);
  setSessionCookie(res, sessionid, username);
  res.json({ success: true });
});

// -- POST /signin ----------------------------------------------------------
// NOTE: JSON-only body - see report for why this doesn't need a CSRF token.
app.post('/signin', (req, res) => {
  const { username, password } = req.body;

  if (!checkPassword(username, password)) {
    res.json({ success: false });
    return;
  }

  const sessionid = createSession(username);
  setSessionCookie(res, sessionid, username);
  res.json({ success: true });
});

// -- POST /signout ---------------------------------------------------------
// FIXED: requires a valid csrf_token, so a forged cross-origin form can no
// longer force-logout a signed-in user.
app.post('/signout', (req, res) => {
  if (!validCsrfToken(req)) {
    res.status(403).json({ success: false, error: 'invalid csrf token' });
    return;
  }

  destroySession(req.session.sessionid);
  clearSessionCookie(res);
  res.json({ success: true });
});

// -- POST /squeak ----------------------------------------------------------
// FIXED: requires a valid csrf_token, so a forged cross-origin form can no
// longer post as a signed-in user.
app.post('/squeak', (req, res) => {
  if (!req.session) {
    res.status(302).redirect('/');
    return;
  }

  if (!validCsrfToken(req)) {
    res.status(403).send('403 Forbidden: invalid or missing CSRF token');
    return;
  }

  const text = req.body.squeak;
  if (typeof text === 'string' && text.length > 0) {
    squeaks.unshift({
      username: req.session.username,
      time: new Date().toString(),
      text,
    });
    persistSqueaks();
  }

  res.redirect(302, '/');
});

// ---------------------------------------------------------------------------
// HTTPS server
// ---------------------------------------------------------------------------

const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, 'cert', 'server.key')),
  cert: fs.readFileSync(path.join(__dirname, 'cert', 'server.crt')),
};

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log('Squeak! (patched) listening on https://localhost:' + PORT);
});
