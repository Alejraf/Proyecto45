// API de WinnerAppMoney en Render, guardando los datos en Firestore (plan Spark, sin tarjeta).
// Mismas rutas y misma URL que antes: la app no cambia.
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const {
  PORT = 3000,
  FIREBASE_SERVICE_ACCOUNT,
  JWT_SECRET,
  ADMIN_KEY,
  POINTS_PER_AD = 10,
  POINTS_PER_USD = 1000,
  MIN_WITHDRAW_USD = 5,
  DAILY_LIMIT = 15,
  ALLOW_DEV_CREDIT = 'false',
} = process.env;
if (!JWT_SECRET || !ADMIN_KEY) throw new Error('Faltan JWT_SECRET y/o ADMIN_KEY');

const PPA = Number(POINTS_PER_AD), PPU = Number(POINTS_PER_USD);
const MIN_USD = Number(MIN_WITHDRAW_USD), LIMIT = Number(DAILY_LIMIT);

let sa;
try { sa = JSON.parse(FIREBASE_SERVICE_ACCOUNT); } catch { throw new Error('FIREBASE_SERVICE_ACCOUNT falta o no es un JSON válido'); }
if (sa.private_key) sa.private_key = sa.private_key.replace(/\\n/g, '\n');
initializeApp({ credential: cert(sa) });
const db = getFirestore();
const users = db.collection('users');
const emails = db.collection('emails');
const rewards = db.collection('rewards');
const withdrawals = db.collection('withdrawals');

const today = () => new Date().toISOString().slice(0, 10);
const sign = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: '90d' });
const emailKey = (e) => crypto.createHash('sha256').update(e).digest('hex');
const ah = (fn) => (req, res, next) => fn(req, res, next).catch(next);

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));
const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 30 });

function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.uid = String(jwt.verify(t, JWT_SECRET).id);
    next();
  } catch { res.status(401).json({ error: 'Sesión inválida. Inicia sesión de nuevo.' }); }
}
const adminOnly = (req, res, next) =>
  req.headers['x-admin-key'] === ADMIN_KEY ? next() : res.status(403).json({ error: 'No autorizado' });

async function me(uid) {
  const u = (await users.doc(uid).get()).data();
  const watched = u.daily && u.daily.day === today() ? u.daily.count : 0;
  return {
    id: uid, email: u.email, points: u.points, usd: u.points / PPU, watched,
    dailyLimit: LIMIT, pointsPerAd: PPA, pointsPerUsd: PPU, minWithdrawUsd: MIN_USD,
  };
}

// ---- Cuenta ----
app.post('/register', authLimiter, ah(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pass = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Correo no válido.' });
  if (pass.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
  const uref = users.doc();
  const eref = emails.doc(emailKey(email));
  try {
    await db.runTransaction(async (tx) => {
      if ((await tx.get(eref)).exists) throw new Error('EXISTS');
      tx.set(eref, { uid: uref.id });
      tx.set(uref, {
        email, pass: bcrypt.hashSync(pass, 10), points: 0,
        daily: { day: today(), count: 0 }, createdAt: FieldValue.serverTimestamp(),
      });
    });
  } catch (e) {
    if (e.message === 'EXISTS') return res.status(409).json({ error: 'Ese correo ya está registrado.' });
    throw e;
  }
  res.json({ token: sign(uref.id), user: await me(uref.id) });
}));

app.post('/login', authLimiter, ah(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const bad = () => res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
  const e = await emails.doc(emailKey(email)).get();
  if (!e.exists) return bad();
  const uid = e.data().uid;
  const u = (await users.doc(uid).get()).data();
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.pass)) return bad();
  res.json({ token: sign(uid), user: await me(uid) });
}));

app.get('/me', auth, ah(async (req, res) => res.json(await me(req.uid))));

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

async function credit(uid, txId) {
  const uref = users.doc(uid);
  const rref = rewards.doc(String(txId).replace(/[^\w-]/g, '_'));
  return db.runTransaction(async (tx) => {
    const [u, r] = await Promise.all([tx.get(uref), tx.get(rref)]);
    if (!u.exists || r.exists) return false;               // usuario inexistente o anuncio ya acreditado
    const d = u.data().daily;
    const count = d && d.day === today() ? d.count : 0;
    if (count >= LIMIT) return false;                       // límite diario
    tx.set(rref, { userId: uid, points: PPA, day: today(), createdAt: FieldValue.serverTimestamp() });
    tx.update(uref, { points: FieldValue.increment(PPA), daily: { day: today(), count: count + 1 } });
    return true;
  });
}

// URL para AdMob: https://TU-DOMINIO/admob/ssv
app.get('/admob/ssv', async (req, res) => {
  try {
    const q = req.url.split('?')[1] || '';
    const idx = q.indexOf('&signature=');
    if (idx < 0) return res.status(400).end();
    const params = new URLSearchParams(q);
    const pem = await getKey(params.get('key_id'));
    if (!pem) return res.status(400).end();
    const ok = crypto.createVerify('SHA256').update(q.slice(0, idx))
      .verify(pem, Buffer.from(params.get('signature'), 'base64url'));
    if (!ok) return res.status(403).end();
    const uid = params.get('user_id'), txId = params.get('transaction_id');
    if (uid && txId) await credit(uid, txId);
    res.status(200).end();
  } catch (e) { console.error('SSV error', e.message); res.status(500).end(); }
});

if (ALLOW_DEV_CREDIT === 'true') {
  app.post('/dev/credit', auth, ah(async (req, res) => {
    await credit(req.uid, 'dev-' + crypto.randomUUID());
    res.json(await me(req.uid));
  }));
}

// ---- Retiros ----
app.post('/withdraw', auth, ah(async (req, res) => {
  const method = String(req.body.method || '').slice(0, 20);
  const account = String(req.body.account || '').trim().slice(0, 120);
  if (!['paypal', 'pix', 'transferencia'].includes(method) || !account)
    return res.status(400).json({ error: 'Indica el método y tu cuenta de cobro.' });
  const uref = users.doc(req.uid);
  const result = await db.runTransaction(async (tx) => {
    const pts = (await tx.get(uref)).data().points;
    if (pts / PPU < MIN_USD) return { error: `El mínimo para retirar es $${MIN_USD.toFixed(2)}.` };
    tx.update(uref, { points: 0 });
    tx.set(withdrawals.doc(), {
      userId: req.uid, points: pts, usd: pts / PPU, method, account,
      status: 'pending', createdAt: FieldValue.serverTimestamp(),
    });
    return { ok: true };
  });
  result.error ? res.status(400).json(result) : res.json(await me(req.uid));
}));

const iso = (t) => (t && t.toDate ? t.toDate().toISOString() : null);

app.get('/withdrawals', auth, ah(async (req, res) => {
  const snap = await withdrawals.where('userId', '==', req.uid).get();
  res.json(snap.docs.map((d) => {
    const w = d.data();
    return { id: d.id, usd: w.usd, method: w.method, status: w.status, created_at: iso(w.createdAt) };
  }).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))));
}));

// ---- Administración (tú) ----
app.get('/admin/withdrawals', adminOnly, ah(async (req, res) => {
  const snap = await withdrawals.where('status', '==', 'pending').get();
  const out = await Promise.all(snap.docs.map(async (d) => {
    const w = d.data();
    const u = await users.doc(w.userId).get();
    return { id: d.id, email: u.exists ? u.data().email : null, usd: w.usd, method: w.method,
      account: w.account, status: w.status, created_at: iso(w.createdAt) };
  }));
  res.json(out.sort((a, b) => String(a.created_at).localeCompare(String(b.created_at))));
}));

app.post('/admin/withdrawals/:id/paid', adminOnly, ah(async (req, res) => {
  const ref = withdrawals.doc(req.params.id);
  await db.runTransaction(async (tx) => {
    const w = await tx.get(ref);
    if (w.exists && w.data().status === 'pending') tx.update(ref, { status: 'paid' });
  });
  res.json({ ok: true });
}));

app.post('/admin/withdrawals/:id/reject', adminOnly, ah(async (req, res) => {
  const ref = withdrawals.doc(req.params.id);
  await db.runTransaction(async (tx) => {
    const w = await tx.get(ref);
    if (!w.exists || w.data().status !== 'pending') return;
    tx.update(ref, { status: 'rejected' });
    tx.update(users.doc(w.data().userId), { points: FieldValue.increment(w.data().points) });
  });
  res.json({ ok: true });
}));

app.get('/health', (_, res) => res.json({ ok: true }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Algo salió mal. Inténtalo de nuevo.' });
});

app.listen(PORT, () => console.log('WinnerAppMoney API en puerto ' + PORT));
