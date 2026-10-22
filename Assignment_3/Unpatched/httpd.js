// Squeak! - DVA489 Assignment 3 - UNPATCHED (vulnerable) version
//
// Deliberately contains:
//   1. Stored XSS   - squeak text is rendered into HTML unescaped
//   2. CSRF         - no token protecting /squeak (or /signin, /signup, /signout)
//   3. ReDoS        - signup compiles the attacker-chosen username into a RegExp
//
// Do not use this file, or patterns from it, outside of this course exercise.

const express = require('express');
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
// ---------------------------------------------------------------------------

let sessions = {}; // sessionid -> username

function createSession(username) {
  const sessionid = crypto.randomBytes(32).toString('hex');
  sessions[sessionid] = username;
  return sessionid;
}

function destroySession(sessionid) {
  delete sessions[sessionid];
}

// Session middleware: reads the squeak-session cookie, verifies it against
// the server-side session table, and exposes the result as req.session.
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

// VULNERABLE: no HttpOnly, no Secure. document.cookie can read this, and it
// would be sent over a plain HTTP connection too, if one existed.
function setSessionCookie(res, sessionid, username) {
  const value = JSON.stringify({ sessionid, username });
  res.cookie('squeak-session', value, { path: '/' });
}

function clearSessionCookie(res) {
  res.clearCookie('squeak-session', { path: '/' });
}

// ---------------------------------------------------------------------------
// Rendering - plain string substitution, no escaping (part of the stored
// XSS vulnerability: squeak text goes straight into the HTML).
// ---------------------------------------------------------------------------

function renderTemplate(name, replacements) {
  const templatePath = path.join(__dirname, 'templates', name);
  let html = fs.readFileSync(templatePath, 'utf8');
  for (const [key, value] of Object.entries(replacements)) {
    html = html.split(`{{${key}}}`).join(value);
  }
  return html;
}

function renderSqueakList() {
  if (squeaks.length === 0) return '';
  return squeaks
    .map(
      (s) => `
      <div class="squeak">
        <div class="squeak-header">
          <span class="squeak-username">${s.username}</span>
          <span class="squeak-time">${s.time}</span>
        </div>
        <div class="squeak-text">${s.text}</div>
      </div>`
    )
    .join('\n');
}

function renderSignInPage(res) {
  const html = renderTemplate('signin.template', {});
  res.status(200).type('html').send(html);
}

function renderFeedPage(res, username) {
  const html = renderTemplate('feed.template', {
    username,
    squeaks: renderSqueakList(),
  });
  res.status(200).type('html').send(html);
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = express();

app.use(cookieParser());
app.use(sessionMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// -- GET / ---------------------------------------------------------------
app.get('/', (req, res) => {
  if (req.session) {
    renderFeedPage(res, req.session.username);
  } else {
    renderSignInPage(res);
  }
});

// -- POST /signup ----------------------------------------------------------
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  const validUsername =
    typeof username === 'string' && username.length >= 4 && !users[username];

  if (!validUsername) {
    res.json({ success: false, field: 'username' });
    return;
  }

  // VULNERABLE: the attacker-chosen username is compiled into a RegExp and
  // run against attacker-chosen input -> ReDoS via catastrophic backtracking.
  let validPassword = password !== undefined && password.length >= 8;
  if (validPassword) {
    let nameregex = new RegExp(username);
    validPassword &= !nameregex.test(password);
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
app.post('/signout', (req, res) => {
  if (req.session) {
    destroySession(req.session.sessionid);
  }
  clearSessionCookie(res);
  res.status(200).end();
});

// -- POST /squeak ------------------------------------------------------------
app.post('/squeak', (req, res) => {
  if (!req.session) {
    res.status(302).redirect('/');
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
  console.log('Squeak! (unpatched) listening on https://localhost:' + PORT);
});
