// Servidor de GanaApp: cuentas, puntos (verificados por AdMob SSV) y retiros.
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

const {
  PORT = 3000,
  JWT_SECRET,
  ADMIN_KEY,
  POINTS_PER_AD = 10,
  POINTS_PER_USD = 1000,
  MIN_WITHDRAW_USD = 5,
  DAILY_LIMIT = 15,
  ALLOW_DEV_CREDIT = 'false',
} = process.env;

if (!JWT_SECRET || !ADMIN_KEY) {
  console.error('Faltan JWT_SECRET y/o ADMIN_KEY (ver .env.example)');
  process.exit(1);
}
const PPA = Number(POINTS_PER_AD), PPU = Number(POINTS_PER_USD);
const MIN_USD = Number(MIN_WITHDRAW_USD), LIMIT = Number(DAILY_LIMIT);

const db = new Database('ganaapp.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  pass TEXT NOT NULL,
  points INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS rewards (
  transaction_id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  points INTEGER NOT NULL,
  day TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS withdrawals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  points INTEGER NOT NULL,
  usd REAL NOT NULL,
  method TEXT NOT NULL,
  account TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);`);

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));
const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 30 });

const today = () => new Date().toISOString().slice(0, 10);
const sign = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '90d' });

function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.uid = jwt.verify(t, JWT_SECRET).id;
    next();
  } catch { res.status(401).json({ error: 'Sesión inválida. Inicia sesión de nuevo.' }); }
}
const adminOnly = (req, res, next) =>
  req.headers['x-admin-key'] === ADMIN_KEY ? next() : res.status(403).json({ error: 'No autorizado' });

function me(uid) {
  const u = db.prepare('SELECT id,email,points FROM users WHERE id=?').get(uid);
  const watched = db.prepare('SELECT COUNT(*) c FROM rewards WHERE user_id=? AND day=?').get(uid, today()).c;
  return { ...u, usd: u.points / PPU, watched, dailyLimit: LIMIT, pointsPerAd: PPA, pointsPerUsd: PPU, minWithdrawUsd: MIN_USD };
}

// ---- Cuenta ----
app.post('/register', authLimiter, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pass = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Correo no válido.' });
  if (pass.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
  try {
    const r = db.prepare('INSERT INTO users (email,pass) VALUES (?,?)').run(email, bcrypt.hashSync(pass, 10));
    res.json({ token: sign({ id: r.lastInsertRowid }), user: me(r.lastInsertRowid) });
  } catch { res.status(409).json({ error: 'Ese correo ya está registrado.' }); }
});

app.post('/login', authLimiter, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.pass))
    return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
  res.json({ token: sign(u), user: me(u.id) });
});

app.get('/me', auth, (req, res) => res.json(me(req.uid)));

// ---- AdMob Server-Side Verification ----
let keyCache = { at: 0, keys: {} };
async function getKey(keyId) {
  if (!keyCache.keys[keyId] || Date.now() - keyCache.at > 24 * 3600_000) {
    const r = await fetch('https://www.gstatic.com/admob/reward/verifier-keys.json');
    const j = await r.json();
    keyCache = { at: Date.now(), keys: Object.fromEntries(j.keys.map((k) => [String(k.keyId), k.pem])) };
  }
  return keyCache.keys[keyId];
}

function credit(uid, txId) {
  const tx = db.transaction(() => {
    const done = db.prepare('SELECT COUNT(*) c FROM rewards WHERE user_id=? AND day=?').get(uid, today()).c;
    if (done >= LIMIT) return false;
    db.prepare('INSERT INTO rewards (transaction_id,user_id,points,day) VALUES (?,?,?,?)').run(txId, uid, PPA, today());
    db.prepare('UPDATE users SET points=points+? WHERE id=?').run(PPA, uid);
    return true;
  });
  return tx();
}

// Configura esta URL en AdMob: https://TU-DOMINIO/admob/ssv
app.get('/admob/ssv', async (req, res) => {
  try {
    const q = req.url.split('?')[1] || '';
    const idx = q.indexOf('&signature=');
    if (idx < 0) return res.status(400).end();
    const message = q.slice(0, idx);
    const params = new URLSearchParams(q);
    const pem = await getKey(params.get('key_id'));
    if (!pem) return res.status(400).end();
    const ok = crypto.createVerify('SHA256').update(message)
      .verify(pem, Buffer.from(params.get('signature'), 'base64url'));
    if (!ok) return res.status(403).end();
    const uid = Number(params.get('user_id'));
    const txId = params.get('transaction_id');
    if (!uid || !txId || !db.prepare('SELECT 1 FROM users WHERE id=?').get(uid)) return res.status(200).end();
    try { credit(uid, txId); } catch { /* transacción repetida: se ignora */ }
    res.status(200).end();
  } catch (e) { console.error('SSV error', e.message); res.status(500).end(); }
});

// Solo pruebas locales (ALLOW_DEV_CREDIT=true). Nunca en producción.
if (ALLOW_DEV_CREDIT === 'true') {
  app.post('/dev/credit', auth, (req, res) => {
    credit(req.uid, 'dev-' + crypto.randomUUID());
    res.json(me(req.uid));
  });
}

// ---- Retiros ----
app.post('/withdraw', auth, (req, res) => {
  const method = String(req.body.method || '').slice(0, 20);
  const account = String(req.body.account || '').trim().slice(0, 120);
  if (!['paypal', 'transferencia'].includes(method) || !account)
    return res.status(400).json({ error: 'Indica el método y tu cuenta de cobro.' });
  const tx = db.transaction(() => {
    const u = db.prepare('SELECT points FROM users WHERE id=?').get(req.uid);
    if (u.points / PPU < MIN_USD) return { error: `El mínimo para retirar es $${MIN_USD.toFixed(2)}.` };
    db.prepare('UPDATE users SET points=0 WHERE id=?').run(req.uid);
    db.prepare('INSERT INTO withdrawals (user_id,points,usd,method,account) VALUES (?,?,?,?,?)')
      .run(req.uid, u.points, u.points / PPU, method, account);
    return { ok: true };
  });
  const r = tx();
  r.error ? res.status(400).json(r) : res.json(me(req.uid));
});

app.get('/withdrawals', auth, (req, res) =>
  res.json(db.prepare('SELECT id,usd,method,status,created_at FROM withdrawals WHERE user_id=? ORDER BY id DESC').all(req.uid)));

// ---- Administración (tú) ----
app.get('/admin/withdrawals', adminOnly, (req, res) =>
  res.json(db.prepare(`SELECT w.*, u.email FROM withdrawals w JOIN users u ON u.id=w.user_id
    WHERE w.status='pending' ORDER BY w.id`).all()));

app.post('/admin/withdrawals/:id/paid', adminOnly, (req, res) => {
  db.prepare("UPDATE withdrawals SET status='paid' WHERE id=? AND status='pending'").run(req.params.id);
  res.json({ ok: true });
});

app.post('/admin/withdrawals/:id/reject', adminOnly, (req, res) => {
  const w = db.prepare("SELECT * FROM withdrawals WHERE id=? AND status='pending'").get(req.params.id);
  if (w) db.transaction(() => {
    db.prepare("UPDATE withdrawals SET status='rejected' WHERE id=?").run(w.id);
    db.prepare('UPDATE users SET points=points+? WHERE id=?').run(w.points, w.user_id);
  })();
  res.json({ ok: true });
});

app.get('/health', (_, res) => res.json({ ok: true }));
app.listen(PORT, () => console.log('GanaApp server en puerto ' + PORT));
