// @home - mock home monitor app. HTTPS server, login with sessions,
// temperature + lights controlled over AJAX.

const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const PORT = 8000;

// cert and key for the self-signed HTTPS certificate
const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, 'cert', 'server.key')),
  cert: fs.readFileSync(path.join(__dirname, 'cert', 'server.crt')),
};

// fake sensor data, stands in for real devices
let data = {
  kitchen: {
    temperature: 21,
    lights: { stove: false, ceiling: false },
  },
  livingroom: {
    temperature: 20,
    lights: { sofa: false, ceiling: false },
  },
  bedroom: {
    temperature: 19,
    lights: { bed: false, ceiling: false },
  },
};

// usernames, each with a per-user salt and a salted+peppered scrypt hash (no plaintext)
const passwdPath = path.join(__dirname, 'passwd');
const credentials = JSON.parse(fs.readFileSync(passwdPath, 'utf8'));

// secret value kept out of the passwd file entirely, ideally set via env in deployment
const PEPPER = process.env.ATHOME_PEPPER || 'dva489-default-pepper';

// combines password + per-user salt + server-wide pepper, then runs a slow hash
function hashPassword(password, salt) {
  return crypto.scryptSync(password + PEPPER, salt, 64).toString('hex');
}

// recomputes the hash for the given password and compares it to what's stored
function checkPassword(username, password) {
  const record = credentials[username];
  if (!record) return false;
  const candidate = hashPassword(password, record.salt);
  const stored = Buffer.from(record.hash, 'hex');
  const attempt = Buffer.from(candidate, 'hex');
  return stored.length === attempt.length && crypto.timingSafeEqual(stored, attempt);
}

// session id -> { username, lastSeen }, username is null for a pre-session (not logged in yet)
let sessions = {};

// sessions go stale after this long with no activity
const SESSION_TIMEOUT_MS = 15 * 60 * 1000;

// hands out a fresh, unguessable session id and marks it as "not logged in yet"
function createPreSession() {
  const id = crypto.randomBytes(32).toString('hex');
  sessions[id] = { username: null, lastSeen: Date.now() };
  return id;
}

// turns the raw Cookie header into a simple key/value object
function parseCookies(req) {
  const header = req.headers.cookie;
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    cookies[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  });
  return cookies;
}

// reads the athome-session cookie from a request
function getSessionId(req) {
  return parseCookies(req)['athome-session'] || null;
}

// true only if the session id is known, has a user attached, and hasn't gone stale.
// also slides the expiry forward on every authenticated request.
function isAuthenticated(req) {
  const id = getSessionId(req);
  const session = id && sessions[id];
  if (!session || !session.username) return false;

  if (Date.now() - session.lastSeen > SESSION_TIMEOUT_MS) {
    delete sessions[id];
    return false;
  }

  session.lastSeen = Date.now();
  return true;
}

// HttpOnly blocks JS from reading the cookie, Secure requires HTTPS, SameSite=Strict
// stops it being sent on cross-site requests
function setSessionCookie(res, id) {
  res.setHeader('Set-Cookie', `athome-session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict`);
}

const mimeTypes = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
};

// serves files out of public/. Not protected by login on purpose, since the
// login page itself needs to load its CSS/JS before anyone is authenticated.
function serveStatic(req, res) {
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(url.parse(req.url).pathname);
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('400 Bad Request: malformed URL encoding');
    return;
  }

  const publicDir = path.join(__dirname, 'public');
  const filePath = path.join(publicDir, decodedPath);

  // filePath must stay inside public/ - blocks ../ escaping the folder
  if (filePath !== publicDir && !filePath.startsWith(publicDir + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('404 Not Found');
      return;
    }

    if (stats.isFile()) {
      const ext = path.extname(filePath);
      const contentType = mimeTypes[ext] || 'application/octet-stream';
      fs.readFile(filePath, (err, content) => {
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
      });
      return;
    }

    if (stats.isDirectory()) {
      const indexPath = path.join(filePath, 'index.html');
      fs.stat(indexPath, (err, indexStats) => {
        if (!err && indexStats.isFile()) {
          fs.readFile(indexPath, (err, content) => {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(content);
          });
        } else {
          res.writeHead(404, { 'Content-Type': 'text/html' });
          res.end('404 Not Found');
        }
      });
    }
  });
}

// turns a POST body like "username=a&password=b" into {username: 'a', password: 'b'}
function parseFormBody(body) {
  const params = {};
  if (!body) return params;
  body.split('&').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = decodeURIComponent(pair.slice(0, idx).replace(/\+/g, ' '));
    const val = decodeURIComponent(pair.slice(idx + 1).replace(/\+/g, ' '));
    params[key] = val;
  });
  return params;
}

// renders the login page and hands out a fresh pre-session cookie every time it loads
function serveLoginPage(res, errorMessage) {
  const templatePath = path.join(__dirname, 'templates', 'login.template');
  fs.readFile(templatePath, 'utf8', (err, template) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('500 Internal Server Error');
      return;
    }

    const errorHtml = errorMessage
      ? `<div class="alert alert-danger">${errorMessage}</div>`
      : '';
    const html = template.replace('{{error}}', errorHtml);

    const preSessionId = createPreSession();
    setSessionCookie(res, preSessionId);

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  });
}

// checks username/password against the passwd file. On success, the pre-session
// cookie already sitting on the request gets upgraded into a real logged-in session.
function handleLogin(req, res) {
  const { username, password } = parseFormBody(req.body);

  if (checkPassword(username, password)) {
    // drop whatever pre-session was on the request and mint a brand new id -
    // stops an attacker who planted a known session id before login (session fixation)
    const oldId = getSessionId(req);
    if (oldId) delete sessions[oldId];

    const id = crypto.randomBytes(32).toString('hex');
    sessions[id] = { username, lastSeen: Date.now() };
    setSessionCookie(res, id);

    res.writeHead(302, { Location: '/' });
    res.end();
    return;
  }

  serveLoginPage(res, 'Invalid username or password');
}

// removes the session tied to this request's cookie, logging the user out
function handleLogout(req, res) {
  const id = getSessionId(req);
  if (id) delete sessions[id];
  res.writeHead(200);
  res.end();
}

function redirectToLogin(res) {
  res.writeHead(302, { Location: '/login' });
  res.end();
}

// fills the main page template with the current temperature/light state
function renderMainPage(res) {
  const templatePath = path.join(__dirname, 'templates', 'main.template');
  fs.readFile(templatePath, 'utf8', (err, template) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('500 Internal Server Error');
      return;
    }

    const html = template
      .replace('{{kitchen_temp}}', data.kitchen.temperature)
      .replace('{{kitchen_stove_class}}', data.kitchen.lights.stove ? 'btn-warning' : 'btn-secondary')
      .replace('{{kitchen_ceiling_class}}', data.kitchen.lights.ceiling ? 'btn-warning' : 'btn-secondary')
      .replace('{{livingroom_temp}}', data.livingroom.temperature)
      .replace('{{livingroom_sofa_class}}', data.livingroom.lights.sofa ? 'btn-warning' : 'btn-secondary')
      .replace('{{livingroom_ceiling_class}}', data.livingroom.lights.ceiling ? 'btn-warning' : 'btn-secondary')
      .replace('{{bedroom_temp}}', data.bedroom.temperature)
      .replace('{{bedroom_bed_class}}', data.bedroom.lights.bed ? 'btn-warning' : 'btn-secondary')
      .replace('{{bedroom_ceiling_class}}', data.bedroom.lights.ceiling ? 'btn-warning' : 'btn-secondary');

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  });
}

// turns a route pattern like "/:room/lights/:light" into a regex, and remembers
// which bits of the path are named params (room, light, ...)
function compileRoute(routePath) {
  const paramNames = [];
  const regexSource = routePath
    .split('/')
    .map((segment) => {
      if (segment.startsWith(':')) {
        paramNames.push(segment.slice(1));
        return '([^/]+)';
      }
      return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return { regex: new RegExp('^' + regexSource + '$'), paramNames };
}

// every route below is a protected resource, checked for a valid session in route()
const getRoutes = [
  { path: '/', handler: (req, res) => renderMainPage(res) },
  { path: '/:room/lights/:light', handler: handleGetLight },
  { path: '/:room/temperature', handler: handleGetTemperature },
];

const postRoutes = [
  { path: '/:room/lights/:light', handler: handlePostLight },
  { path: '/logout', handler: handleLogout },
];

getRoutes.forEach((r) => Object.assign(r, compileRoute(r.path)));
postRoutes.forEach((r) => Object.assign(r, compileRoute(r.path)));

// checks a path against every route in a table, returns the matching handler
// plus the values captured for its named params (e.g. room: "kitchen")
function matchRoutes(routes, pathname) {
  for (const route of routes) {
    const match = route.regex.exec(pathname);
    if (match) {
      const params = {};
      route.paramNames.forEach((name, i) => {
        params[name] = match[i + 1];
      });
      return { handler: route.handler, params };
    }
  }
  return null;
}

function jsonResponse(res, obj) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

// guards against requests for a room/light combination that doesn't exist
function isValidRoomLight(room, light) {
  return data[room] && Object.prototype.hasOwnProperty.call(data[room].lights, light);
}

function handleGetLight(req, res, params) {
  const { room, light } = params;
  if (!isValidRoomLight(room, light)) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'unknown room/light' }));
    return;
  }
  jsonResponse(res, { on: data[room].lights[light] });
}

// flips the light's on/off state and sends back the new state
function handlePostLight(req, res, params) {
  const { room, light } = params;
  if (!isValidRoomLight(room, light)) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'unknown room/light' }));
    return;
  }
  data[room].lights[light] = !data[room].lights[light];
  jsonResponse(res, { on: data[room].lights[light] });
}

function handleGetTemperature(req, res, params) {
  const { room } = params;
  if (!data[room]) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'unknown room' }));
    return;
  }
  jsonResponse(res, { temperature: data[room].temperature });
}

// top-level traffic cop: login is always open, everything else needs a session,
// anything not matched falls through to serving a static file
function route(req, res) {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  if (pathname === '/login') {
    if (req.method === 'GET') return serveLoginPage(res, '');
    if (req.method === 'POST') return handleLogin(req, res);
    res.writeHead(405);
    res.end();
    return;
  }

  const table = req.method === 'GET' ? getRoutes : req.method === 'POST' ? postRoutes : null;
  const matched = table && matchRoutes(table, pathname);

  if (matched) {
    if (!isAuthenticated(req)) {
      redirectToLogin(res);
      return;
    }
    matched.handler(req, res, matched.params);
    return;
  }

  serveStatic(req, res);
}

// reads the full request body first, then hands the request to route()
const server = https.createServer(httpsOptions, (req, res) => {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    req.body = Buffer.concat(chunks).toString();
    console.log(req.method + ' ' + req.url);
    route(req, res);
  });
});

server.listen(PORT, () => {
  console.log('@home server listening on https://localhost:' + PORT);
});
