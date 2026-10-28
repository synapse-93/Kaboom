'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const Busboy = require('busboy');
const { MongoClient, ServerApiVersion } = require('mongodb');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const MAX_FILE = 10 * 1024 * 1024;
const TRANSFER_CHUNK = 3 * 1024 * 1024;
const UPLOAD_LIFETIME_MS = 30 * 60 * 1000;
const TOTAL_QUOTA = 50 * 1024 * 1024;
const UPLOADS_PER_HOUR = 20;
const SESSION_HOURS = 8;
const MAX_BODY = MAX_FILE + 128 * 1024;
const LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const loginAttempts = new Map();
let mongoClient;
let db;
let files;
let sessions;
let controls;
let users;
let pendingUploads;
let uploadChunks;
let ownerUsername;
let uploadQueue = Promise.resolve();
let initialization;

function loadEnvFile() {
  const envPath = path.join(ROOT, '.env');
  let contents;
  try { contents = require('node:fs').readFileSync(envPath, 'utf8'); } catch { return; }
  for (const line of contents.split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || match[1].startsWith('#') || process.env[match[1]] !== undefined) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[match[1]] = value;
  }
}
loadEnvFile();

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);
const DB_NAME = process.env.MONGODB_DB_NAME || 'drop_space';
const LEGACY_DATA_DIR = path.resolve(process.env.LEGACY_DATA_DIR || path.join(ROOT, 'data'));
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const MAX_UPLOADS_IN_FLIGHT = 3;
let activeUploads = 0;

function makeError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function send(res, status, body, type, headers) {
  const responseHeaders = {
    'Content-Type': type || 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    'Cache-Control': 'no-store',
    ...headers
  };
  res.writeHead(status, responseHeaders);
  if (Buffer.isBuffer(body)) return res.end(body);
  if (typeof body === 'string') return res.end(body);
  return res.end(JSON.stringify(body));
}

function fail(res, status, message, headers) {
  return send(res, status, { error: message }, 'application/json; charset=utf-8', headers);
}

function cookieValue(req, name) {
  const prefix = name + '=';
  for (const part of (req.headers.cookie || '').split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return trimmed.slice(prefix.length);
  }
  return '';
}

function cookieOptions(maxAge) {
  return 'Path=/; HttpOnly; SameSite=Strict; Max-Age=' + maxAge + (COOKIE_SECURE ? '; Secure' : '');
}

function sessionIdHash(raw) {
  if (!/^[a-f0-9]{64}$/.test(raw)) return '';
  return crypto.createHash('sha256').update(raw).digest('hex');
}

async function getSession(req) {
  const raw = cookieValue(req, 'drop_session');
  const hash = sessionIdHash(raw);
  if (!hash) return null;
  const session = await sessions.findOne({ _id: hash, expiresAt: { $gt: new Date() } });
  return session || null;
}

async function requireOwner(req, res) {
  try {
    const session = await getSession(req);
    if (!session) {
      fail(res, 401, 'Your session expired. Please sign in again.');
      return null;
    }
    return session;
  } catch {
    fail(res, 503, 'Owner session storage is unavailable. Check the MongoDB connection.');
    return null;
  }
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const expected = (COOKIE_SECURE ? 'https://' : 'http://') + req.headers.host;
  return origin === expected;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let rejected = false;
    req.on('data', chunk => {
      total += chunk.length;
      if (total > limit && !rejected) {
        rejected = true;
        reject(makeError(413, 'Request is too large.'));
        req.resume();
        return;
      }
      if (!rejected) chunks.push(chunk);
    });
    req.on('end', () => { if (!rejected) resolve(Buffer.concat(chunks)); });
    req.on('error', error => { if (!rejected) reject(error); });
  });
}

async function readJson(req, limit) {
  const body = await readBody(req, limit);
  try { return JSON.parse(body.toString('utf8')); } catch { throw makeError(400, 'Request body must be valid JSON.'); }
}

function parseMultipartStream(req) {
  return new Promise((resolve, reject) => {
    let parser;
    try { parser = Busboy({ headers: req.headers, limits: { fileSize: MAX_FILE, files: 1, fields: 2, fieldSize: 256 } }); }
    catch { reject(makeError(400, 'Upload must use a valid multipart form.')); return; }
    let file = null;
    let expiryHours = 24;
    let expiresAtRaw = '';
    let fileSeen = false;
    let failure = null;
    parser.on('file', (field, stream, info) => {
      fileSeen = true;
      if (field !== 'file') { failure = makeError(400, 'Upload form field is invalid.'); stream.resume(); return; }
      const chunks = [];
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('limit', () => { failure = makeError(413, 'File exceeds the 10 MB per-file limit.'); });
      stream.on('end', () => {
        if (!stream.truncated && !failure) file = { filename: info.filename, data: Buffer.concat(chunks) };
      });
    });
    parser.on('field', (name, value) => {
      if (name === 'expiryHours') expiryHours = Number(value.trim());
      if (name === 'expiresAt') expiresAtRaw = value.trim();
    });
    parser.on('filesLimit', () => { failure = makeError(400, 'Upload exactly one file at a time.'); });
    parser.on('fieldsLimit', () => { failure = makeError(400, 'Upload form contains too many fields.'); });
    parser.on('error', () => reject(makeError(400, 'Upload form could not be parsed.')));
    parser.on('finish', () => {
      if (failure) { reject(failure); return; }
      if (!fileSeen || !file || file.data.length === 0) { reject(makeError(400, 'Choose a non-empty file to upload.')); return; }
      let expiry;
      if (expiresAtRaw) expiry = new Date(expiresAtRaw);
      else if (Number.isFinite(expiryHours) && expiryHours > 0) expiry = new Date(Date.now() + expiryHours * 3600000);
      if (!expiry || Number.isNaN(expiry.getTime())) { reject(makeError(400, 'Choose a valid expiry time.')); return; }
      const duration = expiry.getTime() - Date.now();
      if (duration < 60000 || duration > 30 * 24 * 3600000) { reject(makeError(400, 'Expiry must be at least 1 minute and no more than 30 days from now.')); return; }
      resolve({ filename: file.filename, data: file.data, expiresAt: expiry });
    });
    req.pipe(parser);
  });
}

function safeName(input) {
  const cleaned = path.basename(String(input).replace(/[\\/\0]/g, '_')).replace(/[\r\n";]/g, '_').trim().slice(0, 180);
  return cleaned || 'download';
}

function publicRecord(item) {
  return {
    id: String(item._id),
    name: item.name,
    size: item.size,
    createdAt: item.createdAt,
    expiresAt: item.expiresAt,
    downloads: item.downloads || 0,
    revoked: Boolean(item.revoked),
    shareUrl: '/s/' + item.shareToken
  };
}

async function serveStatic(res, filename) {
  try {
    const body = await fs.readFile(path.join(PUBLIC_DIR, filename));
    const extension = path.extname(filename);
    const type = extension === '.html' ? 'text/html; charset=utf-8' : extension === '.css' ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8';
    send(res, 200, body, type);
  } catch {
    fail(res, 404, 'Page not found.');
  }
}

async function withUploadLock(operation) {
  const previous = uploadQueue;
  let release;
  uploadQueue = new Promise(resolve => { release = resolve; });
  await previous;
  try { return await operation(); } finally { release(); }
}

function rateLimitState(key) {
  const now = Date.now();
  const current = loginAttempts.get(key);
  if (!current || now - current.startedAt >= LOGIN_WINDOW_MS) {
    const fresh = { startedAt: now, attempts: 0 };
    loginAttempts.set(key, fresh);
    return fresh;
  }
  return current;
}

function normalizeUsername(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function validUsername(value) {
  return /^[a-z0-9][a-z0-9_-]{2,23}$/.test(value);
}

function makePasswordCredentials(password) {
  const salt = crypto.randomBytes(16);
  return { passwordSalt: salt, passwordHash: crypto.scryptSync(password, salt, 64) };
}

function authenticatePassword(candidate, user) {
  if (typeof candidate !== 'string' || candidate.length > 1024) return false;
  const salt = user?.passwordSalt || Buffer.alloc(16);
  const expected = user?.passwordHash || crypto.scryptSync('invalid-user-password', salt, 64);
  const candidateHash = crypto.scryptSync(candidate, salt, 64);
  return crypto.timingSafeEqual(candidateHash, expected) && Boolean(user);
}

async function createSession(username, res) {
  const rawSession = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_HOURS * 3600000);
  await sessions.insertOne({ _id: sessionIdHash(rawSession), username, createdAt: new Date(), expiresAt });
  return send(res, 200, { ok: true }, undefined, { 'Set-Cookie': 'drop_session=' + rawSession + '; ' + cookieOptions(SESSION_HOURS * 3600) });
}

async function migrateLegacyFiles() {
  await files.updateMany({ scanStatus: { $exists: true } }, { $unset: { scanStatus: '' } });
  const marker = await controls.findOne({ _id: 'legacy-files-v1' });
  if (marker) return;
  let legacy = [];
  try {
    const parsed = JSON.parse(await fs.readFile(path.join(LEGACY_DATA_DIR, 'metadata.json'), 'utf8'));
    if (Array.isArray(parsed)) legacy = parsed;
  } catch (error) {
    if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
  }
  let imported = 0;
  const legacyFilesPath = path.join(LEGACY_DATA_DIR, 'files');
  for (const item of legacy) {
    if (!item || !item.id || !item.token || !item.storedName || path.basename(item.storedName) !== item.storedName) continue;
    if (await files.findOne({ _id: String(item.id) }, { projection: { _id: 1 } })) continue;
    let data;
    try { data = await fs.readFile(path.join(legacyFilesPath, item.storedName)); } catch { continue; }
    if (data.length > MAX_FILE) continue;
    const createdAt = new Date(item.createdAt);
    const expiresAt = new Date(item.expiresAt);
    await files.insertOne({
      _id: String(item.id),
      ownerId: ownerUsername,
      shareToken: String(item.token),
      name: safeName(item.name),
      size: data.length,
      createdAt: Number.isNaN(createdAt.getTime()) ? new Date() : createdAt,
      expiresAt: Number.isNaN(expiresAt.getTime()) ? new Date(0) : expiresAt,
      downloads: Number(item.downloads) || 0,
      revoked: Boolean(item.revoked),
      data
    });
    imported += 1;
  }
  await controls.insertOne({ _id: 'legacy-files-v1', imported, completedAt: new Date() });
  if (imported) console.log('Imported ' + imported + ' legacy file(s) into MongoDB. Local source files were left in place as a backup.');
}

async function initialize() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is missing. Copy .env.example to .env and configure your MongoDB URI.');
  const configuredOwnerUsername = String(process.env.OWNER_USERNAME || 'owner').trim();
  ownerUsername = normalizeUsername(configuredOwnerUsername);
  const ownerPassword = process.env.OWNER_PASSWORD || '';
  if (!validUsername(ownerUsername)) throw new Error('OWNER_USERNAME must be 3-24 characters: letters, numbers, underscore, or hyphen.');
  if (ownerPassword.length < 12 || ownerPassword === 'replace-with-a-strong-private-passphrase') {
    throw new Error('Set OWNER_PASSWORD in .env to a private passphrase of at least 12 characters.');
  }
  mongoClient = new MongoClient(process.env.MONGODB_URI, {
    appName: 'drop-space-file-sharing',
    maxPoolSize: 10,
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
  });
  await mongoClient.connect();
  db = mongoClient.db(DB_NAME);
  await db.command({ ping: 1 });
  files = db.collection('files');
  sessions = db.collection('sessions');
  controls = db.collection('app_control');
  users = db.collection('users');
  pendingUploads = db.collection('pending_uploads');
  uploadChunks = db.collection('upload_chunks');
  if (configuredOwnerUsername !== ownerUsername) {
    await files.updateMany({ ownerId: configuredOwnerUsername }, { $set: { ownerId: ownerUsername } });
  }
  const bootstrapCredentials = makePasswordCredentials(ownerPassword);
  await users.updateOne(
    { _id: ownerUsername },
    { $setOnInsert: { username: ownerUsername, ...bootstrapCredentials, createdAt: new Date(), source: 'environment' } },
    { upsert: true }
  );
  await Promise.all([
    files.createIndex({ shareToken: 1 }, { unique: true, name: 'share_token_unique' }),
    files.createIndex({ ownerId: 1, createdAt: -1 }, { name: 'owner_created' }),
    sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0, name: 'session_expiry' }),
    pendingUploads.createIndex({ uploadDeadline: 1 }, { expireAfterSeconds: 0, name: 'pending_upload_expiry' }),
    pendingUploads.createIndex({ ownerId: 1, uploadDeadline: 1 }, { name: 'owner_pending_uploads' }),
    uploadChunks.createIndex({ uploadDeadline: 1 }, { expireAfterSeconds: 0, name: 'upload_chunk_expiry' }),
    uploadChunks.createIndex({ uploadId: 1, chunkIndex: 1 }, { name: 'upload_chunk_order' })
  ]);
  await migrateLegacyFiles();
}

async function handler(req, res) {
  const url = new URL(req.url, 'http://' + (req.headers.host || (HOST + ':' + PORT)));
  const method = req.method || 'GET';

  if (method === 'GET' && url.pathname === '/login') return serveStatic(res, 'login.html');
  if (method === 'GET' && url.pathname === '/login.js') return serveStatic(res, 'login.js');
  if (method === 'GET' && url.pathname === '/share.js') return serveStatic(res, 'share.js');
  if (method === 'GET' && url.pathname === '/style.css') return serveStatic(res, 'style.css');
  if (method === 'GET' && url.pathname === '/login.css') return serveStatic(res, 'login.css');
  if (method === 'GET' && url.pathname === '/dashboard.css') return serveStatic(res, 'dashboard.css');
  if (method === 'GET' && url.pathname.startsWith('/s/')) return serveStatic(res, 'share.html');

  if (method === 'GET' && url.pathname === '/') {
    const session = await getSession(req);
    if (!session) { res.writeHead(302, { Location: '/login', 'Cache-Control': 'no-store' }); return res.end(); }
    return serveStatic(res, 'index.html');
  }
  if (method === 'GET' && url.pathname === '/app.js') return serveStatic(res, 'app.js');

  if (method === 'POST' && url.pathname === '/api/register') {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    const ip = req.socket.remoteAddress || 'unknown';
    const state = rateLimitState('register:' + ip);
    if (state.attempts >= LOGIN_ATTEMPTS) {
      const retry = Math.max(1, Math.ceil((LOGIN_WINDOW_MS - (Date.now() - state.startedAt)) / 1000));
      return fail(res, 429, 'Too many account creation attempts. Try again in 15 minutes.', { 'Retry-After': String(retry) });
    }
    state.attempts += 1;
    try {
      const body = await readJson(req, 4096);
      const username = normalizeUsername(body.username);
      const password = body.password;
      if (!validUsername(username)) return fail(res, 400, 'Username must be 3-24 characters using letters, numbers, underscores, or hyphens.');
      if (typeof password !== 'string' || password.length < 12 || password.length > 1024) return fail(res, 400, 'Password must be at least 12 characters.');
      const credentials = makePasswordCredentials(password);
      await users.insertOne({ _id: username, username, ...credentials, createdAt: new Date(), source: 'self-service' });
      return await createSession(username, res);
    } catch (error) {
      if (error.code === 11000) return fail(res, 409, 'That username is already in use. Choose another.');
      return fail(res, error.status || 503, error.status ? error.message : 'Account creation is unavailable. Check the MongoDB connection.');
    }
  }

  if (method === 'POST' && url.pathname === '/api/login') {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    const ip = req.socket.remoteAddress || 'unknown';
    const state = rateLimitState(ip);
    if (state.attempts >= LOGIN_ATTEMPTS) {
      const retry = Math.max(1, Math.ceil((LOGIN_WINDOW_MS - (Date.now() - state.startedAt)) / 1000));
      return fail(res, 429, 'Too many sign-in attempts. Try again in 15 minutes.', { 'Retry-After': String(retry) });
    }
    try {
      const body = await readJson(req, 4096);
      const username = normalizeUsername(body.username);
      const user = await users.findOne({ _id: username });
      const passwordOk = authenticatePassword(body.password, user);
      if (!validUsername(username) || !passwordOk) {
        state.attempts += 1;
        return fail(res, 401, 'That username or password is not correct.');
      }
      loginAttempts.delete(ip);
      return await createSession(username, res);
    } catch (error) {
      return fail(res, error.status || 503, error.status ? error.message : 'Sign-in service is unavailable.');
    }
  }

  if (method === 'POST' && url.pathname === '/api/logout') {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    const raw = cookieValue(req, 'drop_session');
    const hash = sessionIdHash(raw);
    if (hash) await sessions.deleteOne({ _id: hash });
    return send(res, 200, { ok: true }, undefined, { 'Set-Cookie': 'drop_session=; ' + cookieOptions(0) });
  }

  let authenticatedUser = null;
  if (url.pathname === '/api/owner' || url.pathname.startsWith('/api/files') || url.pathname.startsWith('/api/uploads') || url.pathname === '/api/session') {
    const session = await requireOwner(req, res);
    if (!session) return;
    authenticatedUser = session;
  }

  if (method === 'GET' && url.pathname === '/api/session') return send(res, 200, { username: authenticatedUser.username });

  if (method === 'GET' && url.pathname === '/api/owner') {
    const [list, usage, uploadsThisHour] = await Promise.all([
      files.find({ ownerId: authenticatedUser.username }, { projection: { data: 0 } }).sort({ createdAt: -1 }).toArray(),
      files.aggregate([{ $match: { ownerId: authenticatedUser.username } }, { $group: { _id: null, bytes: { $sum: '$size' } } }]).toArray(),
      files.countDocuments({ ownerId: authenticatedUser.username, createdAt: { $gte: new Date(Date.now() - 3600000) } })
    ]);
    return send(res, 200, {
      username: authenticatedUser.username,
      files: list.map(publicRecord),
      usedBytes: usage[0]?.bytes || 0,
      quotaBytes: TOTAL_QUOTA,
      maxFileBytes: MAX_FILE,
      uploadsThisHour,
      uploadLimit: UPLOADS_PER_HOUR
    });
  }

  if (method === 'POST' && url.pathname === '/api/uploads') {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    try {
      const body = await readJson(req, 4096);
      const size = Number(body.fileSize);
      if (!Number.isSafeInteger(size) || size < 1 || size > MAX_FILE) return fail(res, 413, 'Choose a non-empty file up to 10 MB.');
      const createdAt = new Date();
      let expiresAt;
      if (body.expiresAt) expiresAt = new Date(body.expiresAt);
      else {
        const expiryHours = Number(body.expiryHours || 24);
        if (!Number.isFinite(expiryHours) || expiryHours <= 0 || expiryHours > 720) return fail(res, 400, 'Choose a valid link expiry.');
        expiresAt = new Date(createdAt.getTime() + expiryHours * 3600000);
      }
      const duration = expiresAt.getTime() - createdAt.getTime();
      if (Number.isNaN(expiresAt.getTime()) || duration < 60000 || duration > 30 * 24 * 3600000) {
        return fail(res, 400, 'Expiry must be at least 1 minute and no more than 30 days from now.');
      }
      const [usage, recentCount, openCount, pendingUsage] = await Promise.all([
        files.aggregate([{ $match: { ownerId: authenticatedUser.username } }, { $group: { _id: null, bytes: { $sum: '$size' } } }]).toArray(),
        files.countDocuments({ ownerId: authenticatedUser.username, createdAt: { $gte: new Date(createdAt.getTime() - 3600000) } }),
        pendingUploads.countDocuments({ ownerId: authenticatedUser.username, uploadDeadline: { $gt: createdAt } }),
        pendingUploads.aggregate([{ $match: { ownerId: authenticatedUser.username, uploadDeadline: { $gt: createdAt } } }, { $group: { _id: null, bytes: { $sum: '$size' } } }]).toArray()
      ]);
      if (recentCount >= UPLOADS_PER_HOUR) return fail(res, 429, 'The limit is 20 uploads per hour. Try again after the oldest upload leaves the rolling hour window.');
      if (openCount >= 3) return fail(res, 429, 'Finish or wait for an existing upload before starting another.');
      if ((usage[0]?.bytes || 0) + (pendingUsage[0]?.bytes || 0) + size > TOTAL_QUOTA) return fail(res, 413, 'This upload would exceed your 50 MB storage quota.');
      const id = crypto.randomUUID();
      const uploadDeadline = new Date(createdAt.getTime() + UPLOAD_LIFETIME_MS);
      const upload = {
        _id: id,
        ownerId: authenticatedUser.username,
        name: safeName(body.filename),
        size,
        chunkCount: Math.ceil(size / TRANSFER_CHUNK),
        expiresAt,
        createdAt,
        uploadDeadline
      };
      await pendingUploads.insertOne(upload);
      return send(res, 201, { uploadId: id, chunkSize: TRANSFER_CHUNK, chunkCount: upload.chunkCount });
    } catch (error) {
      return fail(res, error.status || 503, error.status ? error.message : 'Upload could not be started. Check the MongoDB connection.');
    }
  }

  const chunkRoute = /^\/api\/uploads\/([a-f0-9-]+)\/chunks\/(\d+)$/.exec(url.pathname);
  if (method === 'POST' && chunkRoute) {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    try {
      const upload = await pendingUploads.findOne({ _id: chunkRoute[1], ownerId: authenticatedUser.username, uploadDeadline: { $gt: new Date() } });
      if (!upload) return fail(res, 404, 'Upload not found or it expired. Start the upload again.');
      const chunkIndex = Number(chunkRoute[2]);
      if (!Number.isSafeInteger(chunkIndex) || chunkIndex >= upload.chunkCount) return fail(res, 400, 'Upload chunk number is invalid.');
      const expectedSize = Math.min(TRANSFER_CHUNK, upload.size - chunkIndex * TRANSFER_CHUNK);
      const data = await readBody(req, TRANSFER_CHUNK);
      if (data.length !== expectedSize) return fail(res, 400, 'Upload chunk size did not match. Retry the upload.');
      await uploadChunks.updateOne(
        { _id: upload._id + ':' + chunkIndex, ownerId: authenticatedUser.username },
        { $setOnInsert: { uploadId: upload._id, ownerId: authenticatedUser.username, chunkIndex, size: data.length, data, uploadDeadline: upload.uploadDeadline } },
        { upsert: true }
      );
      return send(res, 200, { ok: true, chunkIndex });
    } catch (error) {
      return fail(res, error.status || 503, error.status ? error.message : 'Upload chunk could not be saved.');
    }
  }

  const completeUpload = /^\/api\/uploads\/([a-f0-9-]+)\/complete$/.exec(url.pathname);
  if (method === 'POST' && completeUpload) {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    const uploadId = completeUpload[1];
    try {
      const existing = await files.findOne({ _id: uploadId, ownerId: authenticatedUser.username });
      if (existing) {
        await Promise.all([pendingUploads.deleteOne({ _id: uploadId, ownerId: authenticatedUser.username }), uploadChunks.deleteMany({ uploadId, ownerId: authenticatedUser.username })]);
        return send(res, 201, { file: publicRecord(existing) });
      }
      const session = mongoClient.startSession();
      let saved;
      try {
        await session.withTransaction(async () => {
          const upload = await pendingUploads.findOne({ _id: uploadId, ownerId: authenticatedUser.username, uploadDeadline: { $gt: new Date() } }, { session });
          if (!upload) throw makeError(404, 'Upload not found or it expired. Start the upload again.');
          const parts = await uploadChunks.find({ uploadId, ownerId: authenticatedUser.username }, { session }).sort({ chunkIndex: 1 }).toArray();
          if (parts.length !== upload.chunkCount || parts.some((part, index) => part.chunkIndex !== index)) throw makeError(400, 'Some upload chunks are missing. Retry the upload.');
          const data = Buffer.concat(parts.map(part => Buffer.isBuffer(part.data) ? part.data : Buffer.from(part.data.buffer || part.data)));
          if (data.length !== upload.size) throw makeError(400, 'Uploaded file size did not match. Start the upload again.');
          const now = new Date();
          const usage = await files.aggregate([{ $match: { ownerId: authenticatedUser.username } }, { $group: { _id: null, bytes: { $sum: '$size' } } }], { session }).toArray();
          const recentCount = await files.countDocuments({ ownerId: authenticatedUser.username, createdAt: { $gte: new Date(now.getTime() - 3600000) } }, { session });
          if ((usage[0]?.bytes || 0) + data.length > TOTAL_QUOTA) throw makeError(413, 'This upload would exceed your 50 MB storage quota.');
          if (recentCount >= UPLOADS_PER_HOUR) throw makeError(429, 'The limit is 20 uploads per hour. Try again after the oldest upload leaves the rolling hour window.');
          saved = {
            _id: upload._id,
            ownerId: authenticatedUser.username,
            shareToken: crypto.randomBytes(32).toString('base64url'),
            name: upload.name,
            size: data.length,
            createdAt: now,
            expiresAt: upload.expiresAt,
            downloads: 0,
            revoked: false,
            data
          };
          await files.insertOne(saved, { session });
          await pendingUploads.deleteOne({ _id: uploadId, ownerId: authenticatedUser.username }, { session });
          await uploadChunks.deleteMany({ uploadId, ownerId: authenticatedUser.username }, { session });
        });
      } finally { await session.endSession(); }
      return send(res, 201, { file: publicRecord(saved) });
    } catch (error) {
      if (error.code === 11000) {
        const existing = await files.findOne({ _id: uploadId, ownerId: authenticatedUser.username });
        if (existing) return send(res, 201, { file: publicRecord(existing) });
      }
      return fail(res, error.status || 503, error.status ? error.message : 'Upload could not be finalized. Check the MongoDB connection.');
    }
  }

  if (method === 'POST' && url.pathname === '/api/files') {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    if (activeUploads >= MAX_UPLOADS_IN_FLIGHT) return fail(res, 429, 'Several uploads are already being processed. Try again shortly.');
    activeUploads += 1;
    try {
      const length = Number(req.headers['content-length'] || 0);
      if (length > MAX_BODY) throw makeError(413, 'Upload exceeds the 10 MB file limit.');
      const upload = await parseMultipartStream(req);
      if (upload.data.length > MAX_FILE) throw makeError(413, 'File exceeds the 10 MB per-file limit.');
      const saved = await withUploadLock(async () => {
        const now = new Date();
        const [used, count] = await Promise.all([
          files.aggregate([{ $match: { ownerId: authenticatedUser.username } }, { $group: { _id: null, bytes: { $sum: '$size' } } }]).toArray(),
          files.countDocuments({ ownerId: authenticatedUser.username, createdAt: { $gte: new Date(now.getTime() - 3600000) } })
        ]);
        if ((used[0]?.bytes || 0) + upload.data.length > TOTAL_QUOTA) throw makeError(413, 'This upload would exceed the 50 MB owner storage quota.');
        if (count >= UPLOADS_PER_HOUR) {
          const oldest = await files.find({ ownerId: authenticatedUser.username, createdAt: { $gte: new Date(now.getTime() - 3600000) } }).sort({ createdAt: 1 }).limit(1).next();
          const seconds = oldest ? Math.max(1, Math.ceil((oldest.createdAt.getTime() + 3600000 - now.getTime()) / 1000)) : 3600;
          throw Object.assign(makeError(429, 'The limit is 20 uploads per hour. Try again after the oldest upload leaves the rolling hour window.'), { retryAfter: seconds });
        }
        const doc = {
          _id: crypto.randomUUID(),
          ownerId: authenticatedUser.username,
          shareToken: crypto.randomBytes(32).toString('base64url'),
          name: safeName(upload.filename),
          size: upload.data.length,
          createdAt: now,
          expiresAt: upload.expiresAt,
          downloads: 0,
          revoked: false,
          data: upload.data
        };
        await files.insertOne(doc);
        return doc;
      });
      return send(res, 201, { file: publicRecord(saved) });
    } catch (error) {
      return fail(res, error.status || 500, error.status ? error.message : 'Upload could not be saved. Check the MongoDB connection.', error.retryAfter ? { 'Retry-After': String(error.retryAfter) } : undefined);
    } finally {
      activeUploads -= 1;
    }
  }

  const expiryEdit = /^\/api\/files\/([a-f0-9-]+)\/expiry$/.exec(url.pathname);
  if (expiryEdit && method === 'POST') {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    try {
      const body = await readJson(req, 4096);
      const expiresAt = new Date(body.expiresAt);
      const duration = expiresAt.getTime() - Date.now();
      if (Number.isNaN(expiresAt.getTime()) || duration < 60000 || duration > 30 * 24 * 3600000) {
        return fail(res, 400, 'Expiry must be at least 1 minute and no more than 30 days from now.');
      }
      const result = await files.updateOne(
        { _id: expiryEdit[1], ownerId: authenticatedUser.username, revoked: false },
        { $set: { expiresAt, expiryUpdatedAt: new Date() } }
      );
      if (!result.matchedCount) return fail(res, 404, 'File not found or its link has been revoked.');
      return send(res, 200, { ok: true, expiresAt });
    } catch (error) {
      return fail(res, error.status || 500, error.status ? error.message : 'Expiry could not be saved. Check the MongoDB connection.');
    }
  }

  const action = /^\/api\/files\/([a-f0-9-]+)\/(revoke|delete)$/.exec(url.pathname);
  if (action && method === 'POST') {
    if (!sameOrigin(req)) return fail(res, 403, 'Request origin was rejected.');
    const id = action[1];
    if (action[2] === 'revoke') {
      const result = await files.updateOne({ _id: id, ownerId: authenticatedUser.username }, { $set: { revoked: true, revokedAt: new Date() } });
      if (!result.matchedCount) return fail(res, 404, 'File not found.');
      return send(res, 200, { ok: true });
    }
    const result = await files.deleteOne({ _id: id, ownerId: authenticatedUser.username });
    if (!result.deletedCount) return fail(res, 404, 'File not found.');
    return send(res, 200, { ok: true });
  }

  if (method === 'GET' && url.pathname.startsWith('/api/share/')) {
    const token = url.pathname.slice('/api/share/'.length);
    const item = await files.findOne({ shareToken: token });
    if (!item) return fail(res, 404, 'This share link is invalid.');
    if (item.revoked) return fail(res, 410, 'The owner revoked this share link.');
    if (Date.now() >= item.expiresAt.getTime()) return fail(res, 410, 'This share link has expired.');
    return send(res, 200, { name: item.name, size: item.size, expiresAt: item.expiresAt, downloadUrl: '/api/download/' + item.shareToken });
  }

  const chunkDownload = /^\/api\/download\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
  if (method === 'GET' && chunkDownload) {
    const offset = Number(url.searchParams.get('offset') || 0);
    if (!Number.isSafeInteger(offset) || offset < 0) return fail(res, 400, 'Download chunk offset is invalid.');
    let item;
    if (offset === 0) {
      item = await files.findOneAndUpdate(
        { shareToken: chunkDownload[1], revoked: false, expiresAt: { $gt: new Date() } },
        { $inc: { downloads: 1 } },
        { returnDocument: 'after' }
      );
    } else {
      item = await files.findOne({ shareToken: chunkDownload[1], revoked: false, expiresAt: { $gt: new Date() } });
    }
    if (!item) {
      const known = await files.findOne({ shareToken: chunkDownload[1] }, { projection: { revoked: 1, expiresAt: 1 } });
      if (!known) return fail(res, 404, 'This share link is invalid.');
      if (known.revoked) return fail(res, 410, 'The owner revoked this share link.');
      return fail(res, 410, 'This share link has expired.');
    }
    if (offset >= item.size) return fail(res, 416, 'Download chunk offset is out of range.');
    const data = Buffer.isBuffer(item.data) ? item.data : Buffer.from(item.data.buffer || item.data);
    const end = Math.min(item.size, offset + TRANSFER_CHUNK);
    const part = data.subarray(offset, end);
    return send(res, 206, part, 'application/octet-stream', {
      'Content-Length': String(part.length),
      'Content-Range': 'bytes ' + offset + '-' + (end - 1) + '/' + item.size,
      'Accept-Ranges': 'bytes'
    });
  }

  if (method === 'GET' && url.pathname.startsWith('/download/')) {
    const token = url.pathname.slice('/download/'.length);
    const active = await files.findOneAndUpdate(
      { shareToken: token, revoked: false, expiresAt: { $gt: new Date() } },
      { $inc: { downloads: 1 } },
      { returnDocument: 'after' }
    );
    const item = active;
    if (!item) {
      const known = await files.findOne({ shareToken: token }, { projection: { revoked: 1, expiresAt: 1 } });
      if (!known) return fail(res, 404, 'This share link is invalid.');
      if (known.revoked) return fail(res, 410, 'The owner revoked this share link.');
      return fail(res, 410, 'This share link has expired.');
    }
    const data = Buffer.isBuffer(item.data) ? item.data : Buffer.from(item.data.buffer || item.data);
    const name = safeName(item.name);
    return send(res, 200, data, 'application/octet-stream', {
      'Content-Length': String(data.length),
      'Content-Disposition': 'attachment; filename="' + name + '"; filename*=UTF-8\'\'' + encodeURIComponent(item.name)
    });
  }

  return fail(res, 404, 'Page not found.');
}

async function ensureInitialized() {
  if (!initialization) {
    initialization = initialize().catch(error => {
      initialization = null;
      throw error;
    });
  }
  return initialization;
}

async function start() {
  await ensureInitialized();
  const server = http.createServer((req, res) => {
    handler(req, res).catch(error => {
      if (!res.headersSent) fail(res, error.status || 500, error.status ? error.message : 'Something went wrong.');
      else res.destroy();
    });
  });
  server.listen(PORT, HOST, () => {
    console.log('Drop Space connected to MongoDB database "' + DB_NAME + '" at http://' + HOST + ':' + PORT);
  });
  const close = async () => {
    server.close();
    if (mongoClient) await mongoClient.close();
    process.exit(0);
  };
  process.on('SIGINT', close);
  process.on('SIGTERM', close);
}

if (require.main === module) {
  start().catch(error => {
    console.error('Could not start Drop Space:', error.message);
    process.exitCode = 1;
  });
} else {
  module.exports = async function vercelHandler(req, res) {
    try {
      await ensureInitialized();
      const url = new URL(req.url, 'https://' + (req.headers.host || 'vercel.local'));
      if (url.pathname === '/api/download' && url.searchParams.has('token')) {
        req.url = '/api/download/' + encodeURIComponent(url.searchParams.get('token')) + (url.searchParams.has('offset') ? '?offset=' + encodeURIComponent(url.searchParams.get('offset')) : '');
      }
      return await handler(req, res);
    } catch (error) {
      if (!res.headersSent) return fail(res, error.status || 500, error.status ? error.message : 'Something went wrong.');
      res.destroy();
    }
  };
}
