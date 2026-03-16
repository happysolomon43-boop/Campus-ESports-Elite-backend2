/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CEE — CAMPUS eSPORTS ELITE
 * Express Backend v2.0 — Railway (Node.js 18)
 * Converted from Firebase Cloud Functions (3018-line source, all fixes included)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * ENVIRONMENT VARIABLES — set in Railway dashboard → Variables tab:
 *   FIREBASE_SERVICE_ACCOUNT   Full service-account JSON as one line (no newlines)
 *   FIREBASE_STORAGE_BUCKET    e.g. ceeapp-2007.firebasestorage.app
 *   GEMINI_KEY_1               Google AI Studio key #1 (primary)
 *   GEMINI_KEY_2               Google AI Studio key #2 (optional, rotates when #1 hits quota)
 *   GEMINI_KEY_3               Google AI Studio key #3 (optional)
 *   GEMINI_KEY_4               Google AI Studio key #4 (optional)
 *                               Get free keys at aistudio.google.com — 1500 req/day each
 *   BREVO_KEY_1                Brevo API key for account #1 (free at app.brevo.com)
 *   BREVO_FROM_1               Sender email for account #1 (the Gmail you signed up with)
 *   BREVO_KEY_2                Brevo API key for account #2 (optional, +295 emails/day)
 *   BREVO_FROM_2               Sender email for account #2
 *   TELEGRAM_TOKEN             Telegram Bot API token
 *   TELEGRAM_ADMIN_CHAT_ID     Admin Telegram chat ID
 *   ADMIN_EMAIL                Admin email address
 *   ADMIN_PLAYER_ID            Admin player doc ID (optional)
 *   ADMIN_SECRET               Strong random string — guards all admin endpoints
 *   PAYSTACK_SECRET            sk_live_... or sk_test_... (blank = test/bypass mode)
 *   PORT                       Set automatically by Railway — do NOT set manually
 *
 * TELEGRAM WEBHOOK (run once after deploy):
 *   curl "https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://<railway-url>/telegramWebhook"
 */

'use strict';

const express      = require('express');
const corsMidd     = require('cors');
const cron         = require('node-cron');
const admin        = require('firebase-admin');
const { DateTime } = require('luxon');
// nodemailer removed — using SendGrid HTTP API (Railway-compatible, no SMTP port needed)
const crypto       = require('crypto');
const bcrypt       = require('bcrypt');
const fetch        = require('node-fetch');

// ── Firebase Admin init ───────────────────────────────────────────────────
let serviceAccount;
try {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT || '{}';
  serviceAccount = JSON.parse(raw);
} catch(e) {
  console.error('[CEE] FATAL: FIREBASE_SERVICE_ACCOUNT is not valid JSON:', e.message);
  console.error('[CEE] Make sure the value in Railway has no line breaks and is a single-line JSON string.');
  serviceAccount = {};
}
admin.initializeApp({
  credential:    admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET || ''
});
const db      = admin.firestore();
const storage = admin.storage();

// ── Environment config (replaces functions.config()) ─────────────────────
const env = {
  gemini:   { key: process.env.GEMINI_KEY_1 || process.env.GEMINI_KEY }, // legacy GEMINI_KEY still works
  gmail:    { user: null, pass: null }, // kept for legacy reference only — email now uses SendGrid
  telegram: { token:         process.env.TELEGRAM_TOKEN,
              admin_chat_id: process.env.TELEGRAM_ADMIN_CHAT_ID },
  admin:    { email:         process.env.ADMIN_EMAIL,
              player_id:     process.env.ADMIN_PLAYER_ID,
              secret:        process.env.ADMIN_SECRET },
  paystack: { secret:        process.env.PAYSTACK_SECRET }
};

// ── Gemini key pool — rotates across up to 4 keys (mirrors Brevo strategy) ────────
// Each key is a free Google AI Studio key (1500 req/day).
// 4 keys = up to 6000 Gemini calls/day across all features.
// Set GEMINI_KEY_1 through GEMINI_KEY_4 in Railway → Variables.
// GEMINI_KEY (no suffix) is also accepted as a legacy alias for key #1.
const _geminiKeys = [];
for (let _gi = 1; _gi <= 4; _gi++) {
  const _k = process.env[`GEMINI_KEY_${_gi}`] || (_gi === 1 ? process.env.GEMINI_KEY : null);
  if (_k && _k.trim()) _geminiKeys.push({ key: _k.trim(), callsToday: 0, lastResetDate: '' });
}
if (_geminiKeys.length > 0) {
  console.log(`[CEE] Gemini: ${_geminiKeys.length} key(s) loaded — up to ${_geminiKeys.length * 1500} req/day`);
} else {
  console.warn('[CEE] Gemini: No keys configured. Add GEMINI_KEY_1 in Railway → Variables (free at aistudio.google.com).');
}

let _geminiRoundRobinIdx = 0;

function _resetGeminiKeyIfNewDay(k) {
  const today = nowWAT().toISODate();
  if (k.lastResetDate !== today) {
    k.exhausted = false;    // new day — quota resets regardless of what it was
    k.callsToday = 0;
    k.lastResetDate = today;
  }
}

// Pick next available key using round-robin — skips keys marked exhausted today
// No hardcoded quota limit: exhausted flag is ONLY set when the API returns 429.
function _pickGeminiKey() {
  if (!_geminiKeys.length) return null;
  for (let attempt = 0; attempt < _geminiKeys.length; attempt++) {
    const idx = (_geminiRoundRobinIdx + attempt) % _geminiKeys.length;
    const k = _geminiKeys[idx];
    _resetGeminiKeyIfNewDay(k);
    if (!k.exhausted) {
      _geminiRoundRobinIdx = (idx + 1) % _geminiKeys.length;
      return k;
    }
  }
  return null; // all keys hit 429 today
}

function _geminiUrl(k) {
  return `https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=${k.key}`;
}

// ── Gemini 2.5 Pro — used ONLY for scout analysis (large context text tasks) ─
// Flash is kept for all other calls (vision/fraud detection, small tasks).
// Pro handles the 5-match stat dump + trend report context reliably.
function _geminiProUrl(k) {
  return `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${k.key}`;
}

async function _geminiProPost(bodyObj) {
  let lastErr = null;
  for (let attempt = 0; attempt < Math.max(_geminiKeys.length, 1); attempt++) {
    const k = _pickGeminiKey();
    if (!k) return { ok: false, error: 'All Gemini keys hit their quota for today. Add more via GEMINI_KEY_2/3/4 in Railway.' };
    try {
      const r = await fetch(_geminiProUrl(k), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyObj)
      });
      k.callsToday++;
      if (r.status === 429) {
        k.exhausted = true;
        lastErr = 'quota_exceeded';
        console.warn(`[CEE] Gemini Pro key #${_geminiKeys.indexOf(k)+1} exhausted (429) after ${k.callsToday} calls today — rotating`);
        continue;
      }
      const data = await r.json();
      return { ok: true, data };
    } catch(e) {
      lastErr = e.message;
      console.error(`[CEE] Gemini Pro call error (attempt ${attempt+1}):`, e.message);
    }
  }
  return { ok: false, error: lastErr || 'Gemini Pro call failed' };
}

// Wrapper: pick key, call Gemini, rotate on 429, retry with next key automatically
async function _geminiPost(bodyObj) {
  let lastErr = null;
  for (let attempt = 0; attempt < Math.max(_geminiKeys.length, 1); attempt++) {
    const k = _pickGeminiKey();
    if (!k) return { ok: false, error: 'All Gemini keys hit their quota for today. Add more via GEMINI_KEY_2/3/4 in Railway.' };
    try {
      const r = await fetch(_geminiUrl(k), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyObj)
      });
      k.callsToday++;
      if (r.status === 429) {
        k.exhausted = true; // quota hit — let the API decide, not us
        lastErr = 'quota_exceeded';
        console.warn(`[CEE] Gemini key #${_geminiKeys.indexOf(k)+1} exhausted (429) after ${k.callsToday} calls today — rotating`);
        continue;
      }
      const data = await r.json();
      return { ok: true, data };
    } catch(e) {
      lastErr = e.message;
      console.error(`[CEE] Gemini call error (attempt ${attempt+1}):`, e.message);
    }
  }
  return { ok: false, error: lastErr || 'Gemini call failed' };
}

// ── Gemini key pool ──────────────────────────────────────────────────────────

// ── VAPID / Web Push ──────────────────────────────────────────────────────
const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_SUBJECT     = `mailto:${process.env.ADMIN_EMAIL || 'admin@cee.app'}`;

let _vapidPrivKeyObj = null;
let _vapidPubKeyBuf  = null;

function _initVapid() {
  if (_vapidPrivKeyObj) return true;
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    console.warn('[CEE] VAPID keys not set — web push disabled. Set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY in Railway.');
    return false;
  }
  try {
    _vapidPubKeyBuf = Buffer.from(VAPID_PUBLIC_KEY, 'base64url');
    // Build PKCS#8 DER for P-256 private key from the raw 32-byte private scalar.
    // Using DER avoids the JWK path which validates d against (x,y) and can fail
    // with "Invalid JWK EC key" on certain Node builds even with valid keys.
    // Header = SEQUENCE { version INTEGER 0, AlgorithmIdentifier { ecPublicKey, prime256v1 },
    //           OCTET STRING { ECPrivateKey SEQUENCE { version 1, OCTET STRING[32] } } }
    const pkcs8Header = Buffer.from(
      '3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420',
      'hex'
    );
    const privKeyBytes = Buffer.from(VAPID_PRIVATE_KEY, 'base64url');
    if (privKeyBytes.length !== 32) throw new Error(`Private key must be 32 bytes, got ${privKeyBytes.length}`);
    _vapidPrivKeyObj = crypto.createPrivateKey({
      key:    Buffer.concat([pkcs8Header, privKeyBytes]),
      format: 'der',
      type:   'pkcs8'
    });
    console.log('[CEE] VAPID initialized — web push enabled.');
    return true;
  } catch(e) {
    console.error('[CEE] VAPID init failed:', e.message);
    return false;
  }
}

// HKDF helpers (RFC 5869)
function _hkdfExtract(salt, ikm) {
  return crypto.createHmac('sha256', salt).update(ikm).digest();
}
function _hkdfExpand(prk, info, len) {
  const chunks = [];
  let T = Buffer.alloc(0);
  for (let i = 1; chunks.reduce((a, c) => a + c.length, 0) < len; i++) {
    T = crypto.createHmac('sha256', prk).update(Buffer.concat([T, info, Buffer.from([i])])).digest();
    chunks.push(T);
  }
  return Buffer.concat(chunks).slice(0, len);
}

// Build VAPID JWT (RFC 8292)
function _vapidJwt(endpoint) {
  const url      = new URL(endpoint);
  const audience = `${url.protocol}//${url.host}`;
  const exp      = Math.floor(Date.now() / 1000) + 43200; // 12h
  const header   = Buffer.from(JSON.stringify({ typ:'JWT', alg:'ES256' })).toString('base64url');
  const payload  = Buffer.from(JSON.stringify({ aud:audience, exp, sub:VAPID_SUBJECT })).toString('base64url');
  const input    = `${header}.${payload}`;
  // ieee-p1363 encoding gives raw r||s (64 bytes) — what JWT ES256 expects
  const sig = crypto.sign(null, Buffer.from(input), { key: _vapidPrivKeyObj, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}

// Encrypt push payload (RFC 8291 — aes128gcm)
function _encryptPushPayload(payloadStr, subscription) {
  const recipPubBuf = Buffer.from(subscription.keys.p256dh, 'base64url'); // 65 bytes uncompressed
  const authBuf     = Buffer.from(subscription.keys.auth,   'base64url'); // 16 bytes

  // Random 16-byte salt
  const salt = crypto.randomBytes(16);

  // Ephemeral sender key pair
  const senderPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding:  { type:'spki',  format:'der' },
    privateKeyEncoding: { type:'pkcs8', format:'der' }
  });
  // Raw 65-byte sender public key = last 65 bytes of the SPKI DER
  const senderPubRaw = senderPair.publicKey.slice(-65);
  const senderPrivObj = crypto.createPrivateKey({ key:senderPair.privateKey, format:'der', type:'pkcs8' });

  // Import recipient public key into a Node crypto key object via SPKI DER
  const spkiHdr     = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  const recipPubObj = crypto.createPublicKey({ key:Buffer.concat([spkiHdr, recipPubBuf]), format:'der', type:'spki' });

  // ECDH shared secret
  const ecdhSecret = crypto.diffieHellman({ privateKey:senderPrivObj, publicKey:recipPubObj });

  // IKM derivation (RFC 8291 §3.3)
  const ikmInfo = Buffer.concat([Buffer.from('WebPush: info\0','ascii'), recipPubBuf, senderPubRaw]);
  const prkKey  = _hkdfExtract(authBuf, ecdhSecret);
  const ikm     = _hkdfExpand(prkKey, ikmInfo, 32);

  // Derive CEK (16 bytes) and nonce (12 bytes)
  const prk   = _hkdfExtract(salt, ikm);
  const cek   = _hkdfExpand(prk, Buffer.from('Content-Encoding: aes128gcm\0','ascii'), 16);
  const nonce = _hkdfExpand(prk, Buffer.from('Content-Encoding: nonce\0','ascii'), 12);

  // AES-128-GCM encrypt: plaintext || 0x02 (last-record delimiter)
  const cipher    = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.concat([Buffer.from(payloadStr, 'utf8'), Buffer.from([0x02])])),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag(); // 16 bytes

  // RFC 8291 §4 body: salt(16) || rs(4,BE) || keylen(1) || senderPub(65) || ciphertext || tag
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([65]), senderPubRaw, encrypted, tag]);
}

// Send a single Web Push notification
async function _sendWebPush(subscription, notifPayload) {
  if (!_initVapid()) return { ok:false, error:'VAPID not configured' };
  if (!subscription || !subscription.endpoint || !subscription.keys) return { ok:false, error:'Invalid subscription' };
  try {
    const jwt  = _vapidJwt(subscription.endpoint);
    const body = _encryptPushPayload(JSON.stringify(notifPayload), subscription);
    const res  = await fetch(subscription.endpoint, {
      method:  'POST',
      headers: {
        'Content-Type':     'application/octet-stream',
        'Content-Encoding': 'aes128gcm',
        'Authorization':    `vapid t=${jwt},k=${VAPID_PUBLIC_KEY}`,
        'TTL':              '86400',
        'Urgency':          notifPayload.urgency || 'normal'
      },
      body
    });
    if (res.status === 201 || res.status === 200) return { ok:true };
    if (res.status === 410 || res.status === 404) return { ok:false, expired:true };
    const txt = await res.text().catch(()=>'');
    return { ok:false, error:`Push server: ${res.status} ${txt}` };
  } catch(e) {
    return { ok:false, error:e.message };
  }
}

// Initialise VAPID at server startup
_initVapid();

// ── Startup config validation ─────────────────────────────────────────────
(function _validateConfig() {
  const required = ['TELEGRAM_TOKEN','TELEGRAM_ADMIN_CHAT_ID','ADMIN_EMAIL','ADMIN_SECRET'];
  // Gemini keys are validated via the pool — at least one of GEMINI_KEY_1..4 must exist
  if (!_geminiKeys.length) console.error('[CEE] FATAL: No Gemini keys found. Set GEMINI_KEY_1 in Railway → Variables (free at aistudio.google.com).');
  const missing = required.filter(k => !process.env[k]);
  if (missing.length > 0) {
    console.error(`[CEE] FATAL: Missing env vars: ${missing.join(', ')}`);
    console.error('[CEE] Set them in Railway → Variables before deploying.');
  }
})();

// ── Load tokens from Firestore if not set in Railway env vars ──────────────
// Admin can save TELEGRAM_TOKEN and BREVO keys via Season Clock → API Keys.
// This function bridges: admin UI → Firestore adminSettings → backend runtime.
// Runs once after Firestore is ready. Safe to run even if keys are already set.
async function _loadTokensFromFirestore() {
  try {
    const doc = await db.collection('config').doc('adminSettings').get();
    if (!doc.exists) return;
    const d = doc.data();

    // Telegram token
    if (!env.telegram.token && d.tgToken && /^\d+:[A-Za-z0-9_-]{20,}$/.test(d.tgToken)) {
      env.telegram.token = d.tgToken;
      console.log('[CEE] ✅ TELEGRAM_TOKEN loaded from Firestore adminSettings');
      // Auto-set webhook so players can link immediately
      try {
        const railwayDomain = process.env.RAILWAY_PUBLIC_DOMAIN || process.env.RAILWAY_STATIC_URL;
        if (railwayDomain) {
          const webhookUrl = `https://${railwayDomain}/telegramWebhook`;
          fetch(`https://api.telegram.org/bot${d.tgToken}/setWebhook?url=${encodeURIComponent(webhookUrl)}`)
            .then(r => r.json())
            .then(res => { if (res.ok) console.log('[CEE] ✅ Telegram webhook auto-set to', webhookUrl); })
            .catch(() => {});
        }
      } catch(e) { /* non-fatal */ }
    }
    // Telegram bot username
    if (d.tgBotUsername) {
      env.telegram.botUsername = d.tgBotUsername;
    }

    // Brevo accounts — load if not already configured from env vars
    if (_brevoAccounts.length === 0) {
      // Try Firestore-saved Brevo keys
      for (let i = 1; i <= 4; i++) {
        const key  = d[`brevoKey${i}`];
        const from = d[`brevoFrom${i}`];
        const name = d[`brevoName${i}`] || 'CEE League';
        if (key && from) {
          _brevoAccounts.push({ key, from, name, sentToday: 0, lastResetDate: '' });
          console.log(`[CEE] ✅ Brevo account ${i} loaded from Firestore adminSettings (${from})`);
        }
      }
    }

    // Admin email
    if (!env.admin.email && d.adminEmail) {
      env.admin.email = d.adminEmail;
      console.log('[CEE] ✅ ADMIN_EMAIL loaded from Firestore adminSettings');
    }

  } catch(e) {
    console.warn('[CEE] Could not load tokens from Firestore (non-fatal):', e.message);
  }
}


// ── Express app ───────────────────────────────────────────────────────────
const app = express();
// Handle CORS preflight for ALL routes (must be before any route definitions)
app.options('*', corsMidd({
  origin: '*',
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','x-cee-admin-secret','x-cee-player-pin']
}));
app.use(corsMidd({
  origin: '*',
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','x-cee-admin-secret','x-cee-player-pin']
}));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// ── WAT helpers ───────────────────────────────────────────────────────────
const WAT_ZONE = 'Africa/Lagos';
function nowWAT()    { return DateTime.now().setZone(WAT_ZONE); }
function fromTS(ts)  { return DateTime.fromJSDate(ts.toDate()).setZone(WAT_ZONE); }
function toTS(watDt) { return admin.firestore.Timestamp.fromDate(watDt.toJSDate()); }
function nowTS()     { return admin.firestore.Timestamp.fromDate(nowWAT().toJSDate()); }

// ── Admin secret guard ────────────────────────────────────────────────────
function assertAdminSecret(req, res) {
  const secret   = env.admin && env.admin.secret;
  const provided = req.headers['x-cee-admin-secret'] || (req.body && req.body._adminSecret);
  // If ADMIN_SECRET is not configured, lock down everything — never open by default
  if (!secret || secret.trim().length < 6) {
    res.status(503).json({ success: false, message: 'Admin secret not configured on server. Set ADMIN_SECRET in Railway → Variables.' });
    return false;
  }
  if (!provided || provided !== secret) {
    res.status(403).json({ success: false, message: 'Forbidden' });
    return false;
  }
  return true;
}

// ── Brevo (formerly Sendinblue) multi-account email ──────────────────────
// Railway-compatible — pure HTTPS port 443, never blocked.
// Free tier: 300 emails/day per account. 2 accounts = 600 emails/day.
// No domain needed — works with any Gmail as sender.
//
// Setup:
//   1. Go to app.brevo.com → sign up free with Gmail #1
//   2. Top-right avatar → SMTP & API → API Keys → Generate key → copy it
//   3. Repeat with Gmail #2 for a second account
//   4. Add to Railway → Variables:
//        BREVO_KEY_1    = your-first-brevo-api-key
//        BREVO_FROM_1   = gmail1@gmail.com   (the Gmail you signed up with)
//        BREVO_NAME_1   = CEE League         (sender display name — optional)
//        BREVO_KEY_2    = your-second-brevo-api-key
//        BREVO_FROM_2   = gmail2@gmail.com
//        BREVO_NAME_2   = CEE League

// Build the pool of configured Brevo accounts at startup
const _brevoAccounts = [];
for (let i = 1; i <= 4; i++) {
  const key  = process.env[`BREVO_KEY_${i}`];
  const from = process.env[`BREVO_FROM_${i}`];
  const name = process.env[`BREVO_NAME_${i}`] || 'CEE League';
  if (key && from) {
    _brevoAccounts.push({ key, from, name, sentToday: 0, lastResetDate: '' });
  }
}
if (_brevoAccounts.length > 0) {
  console.log(`[CEE] Brevo: ${_brevoAccounts.length} account(s) loaded — up to ${_brevoAccounts.length * 295} emails/day`);
} else {
  console.warn('[CEE] Brevo: No accounts configured. Add BREVO_KEY_1 + BREVO_FROM_1 in Railway → Variables.');
}

// Daily counter reset — resets each account's count at midnight WAT
function _brevoResetIfNewDay(acct) {
  const today = nowWAT().toISODate();
  if (acct.lastResetDate !== today) {
    acct.sentToday = 0;
    acct.lastResetDate = today;
  }
}

// Pick the next available account under the 295-email soft limit
// (295 not 300 — small safety buffer)
function _pickBrevoAccount() {
  for (const acct of _brevoAccounts) {
    _brevoResetIfNewDay(acct);
    if (acct.sentToday < 295) return acct;
  }
  return null; // all accounts exhausted for today
}

// ── Core Brevo send (single account, single email) ───────────────────────
async function _sendViaBrevo(acct, to, subject, htmlBody) {
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method:  'POST',
      headers: {
        'api-key':      acct.key,
        'Content-Type': 'application/json',
        'Accept':       'application/json'
      },
      body: JSON.stringify({
        sender:      { name: acct.name, email: acct.from },
        to:          [{ email: to }],
        subject:     subject,
        htmlContent: emailHtml(subject, htmlBody)
      })
    });

    // Brevo returns 201 Created on success
    if (r.status === 201 || r.status === 200) {
      acct.sentToday++;
      console.log(`[CEE] Email sent via Brevo (${acct.from}) to ${to} | today: ${acct.sentToday}/295`);
      return { success: true };
    }

    // Parse error
    let errMsg = `Brevo HTTP ${r.status}`;
    try {
      const body = await r.json();
      errMsg = body.message || body.error || errMsg;
    } catch(_) {}

    if (r.status === 401) errMsg = 'Brevo API key invalid — check BREVO_KEY in Railway Variables.';
    if (r.status === 403) errMsg = 'Brevo account not authorised — check your Brevo account is active.';
    if (r.status === 429) { acct.sentToday = 300; errMsg = 'Brevo daily limit reached for ' + acct.from; }

    return { success: false, error: errMsg };
  } catch(e) {
    return { success: false, error: e.message };
  }
}

// ── sendEmail — rotates across all configured Brevo accounts ─────────────
async function sendEmail(to, subject, htmlBody) {
  if (_brevoAccounts.length === 0) {
    const msg = 'No Brevo accounts configured. Add BREVO_KEY_1 + BREVO_FROM_1 in Railway → Variables. ' +
                'Sign up free at app.brevo.com — 300 emails/day per account, no domain needed.';
    console.error('[CEE] sendEmail:', msg);
    return { success: false, error: msg };
  }

  const acct = _pickBrevoAccount();
  if (!acct) {
    const msg = `All ${_brevoAccounts.length} Brevo account(s) have reached their 295 email/day limit. ` +
                'Add a second account (BREVO_KEY_2 + BREVO_FROM_2) or wait until midnight WAT for limits to reset.';
    console.warn('[CEE] sendEmail:', msg);
    return { success: false, error: msg };
  }

  const result = await _sendViaBrevo(acct, to, subject, htmlBody);

  // If this account hit its daily limit, automatically retry with the next available account
  if (!result.success && (result.error || '').includes('daily limit')) {
    const fallback = _pickBrevoAccount();
    if (fallback && fallback !== acct) {
      console.warn(`[CEE] Account ${acct.from} hit limit — retrying with ${fallback.from}`);
      return _sendViaBrevo(fallback, to, subject, htmlBody);
    }
  }

  return result;
}

// ── Telegram helper ───────────────────────────────────────────────────────
async function sendTelegram(chatId, text) {
  if (!chatId || !env.telegram || !env.telegram.token) return null;
  try {
    const r = await fetch(
      `https://api.telegram.org/bot${env.telegram.token}/sendMessage`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' }) }
    );
    return r.json();
  } catch (e) { console.error('[CEE] Telegram error:', e.message); return null; }
}

// ── HTML email template (CEE branding) ───────────────────────────────────
function emailHtml(subject, bodyHtml) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body{background:#111119;font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:0}
  .w{max-width:600px;margin:0 auto;background:#1E1E2C;border:1px solid rgba(240,165,0,.18)}
  .h{background:linear-gradient(135deg,#C8860A,#F0A500);padding:24px 32px}
  .ht{color:#000;font-size:18px;font-weight:700;letter-spacing:.05em;margin:0}
  .hs{color:rgba(0,0,0,.65);font-size:11px;letter-spacing:.14em;text-transform:uppercase;margin-top:4px}
  .b{padding:32px}.b p{color:#BBBBC8;font-size:14px;line-height:1.8;margin:0 0 14px}
  .b strong{color:#EEEEF8}
  .hl{background:rgba(240,165,0,.08);border-left:3px solid #F0A500;padding:12px 16px;margin:16px 0;color:#F0A500;font-size:13px}
  .f{border-top:1px solid rgba(240,165,0,.1);padding:20px 32px;text-align:center}
  .f p{color:rgba(136,136,160,.5);font-size:11px;margin:0}
</style></head><body>
<div class="w">
<div class="h"><div class="ht">⚡ CEE — Campus eSports Elite</div><div class="hs">${subject}</div></div>
<div class="b">${bodyHtml}</div>
<div class="f"><p>Campus eSports Elite · Nigeria Campus League · Automated notification</p></div>
</div></body></html>`;
}



// ── WhatsApp relay helper — generates wa.me link for admin to forward ─────
// Called alongside email/telegram when a player has a whatsappNumber.
// Stores a pending relay record in notifications so admin can tap to send.
async function _queueWhatsAppRelay(fixtureId, playerId, playerData, messageText) {
  if (!playerData.whatsappNumber) return;
  const clean = String(playerData.whatsappNumber).replace(/\D/g,'');
  if (!clean) return;
  const encoded = encodeURIComponent(messageText.replace(/<[^>]+>/g,'').trim()); // strip HTML tags
  const waLink  = `https://wa.me/${clean}?text=${encoded}`;
  await db.collection('notifications').add({
    fixtureId:     fixtureId || null,
    recipientId:   playerId,
    recipientName: playerData.clubName || playerData.gameName || playerId,
    channel:       'whatsapp_relay',
    eventType:     'WHATSAPP_RELAY',
    sentAt:        admin.firestore.FieldValue.serverTimestamp(),
    status:        'pending_relay',
    retryCount:    0,
    waLink,
    messageText:   messageText.replace(/<[^>]+>/g,'').trim().substring(0, 500),
    whatsappNumber: clean
  }).catch(()=>{});
}

// ── Notification logger — NOI-3: stores payload for retry reconstruction ──
async function logNotif(fixtureId, recipientId, channel, eventType, status, err, payload) {
  const doc = {
    fixtureId: fixtureId || null, recipientId, channel, eventType,
    sentAt: admin.firestore.FieldValue.serverTimestamp(),
    status, retryCount: 0, messageId: null, errorMessage: err || null
  };
  if (payload) {
    if (payload.messageText)    doc.messageText    = payload.messageText;
    if (payload.emailSubject)   doc.emailSubject   = payload.emailSubject;
    if (payload.emailHtmlBody)  doc.emailHtmlBody  = payload.emailHtmlBody;
    if (payload.telegramChatId) doc.telegramChatId = payload.telegramChatId;
    if (payload.email)          doc.email          = payload.email;
  }
  return db.collection('notifications').add(doc);
}

// ── Audit log helper ──────────────────────────────────────────────────────
async function audit(action, targetId, targetType, detail, prev, next) {
  return db.collection('adminAuditLog').add({
    action, targetId, targetType, performedBy: 'system',
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
    detail,
    previousValue: prev !== undefined ? prev : null,
    newValue:      next !== undefined ? next : null
  });
}

// ── getSeasonId — DI-2: 5-min TTL cache ──────────────────────────────────
let _cachedSeasonId = null, _cachedSeasonIdAt = 0;
const SEASON_ID_TTL_MS = 5 * 60 * 1000;
async function getSeasonId() {
  const now = Date.now();
  if (_cachedSeasonId && (now - _cachedSeasonIdAt) < SEASON_ID_TTL_MS) return _cachedSeasonId;
  const doc = await db.collection('config').doc('season').get();
  _cachedSeasonId   = doc.exists ? (doc.data().activeSeasonId || null) : null;
  _cachedSeasonIdAt = now;
  return _cachedSeasonId;
}
function _invalidateSeasonIdCache() { _cachedSeasonId = null; _cachedSeasonIdAt = 0; }

async function getPlayers(seasonId) {
  const snap = await db.collection('players').where('seasonId','==',seasonId).get();
  const out = []; snap.forEach(d => out.push({ id: d.id, ...d.data() })); return out;
}
async function getFixtures(seasonId) {
  const snap = await db.collection('fixtures').where('seasonId','==',seasonId).get();
  const out = []; snap.forEach(d => out.push({ id: d.id, ...d.data() })); return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL NOTIFICATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════
// ── _notifyPlayer — central helper, tries ALL channels a player has ────────
// Priority: Telegram → Email → WhatsApp relay (always queued if number exists)
async function _notifyPlayer(pid, fixtureId, eventType, subject, htmlBody, tgText) {
  if (!pid) return;
  const snap = await db.collection('players').doc(pid).get();
  if (!snap.exists) return;
  const p = { id: pid, ...snap.data() };
  const results = { telegram: null, email: null, whatsapp: null, push: null };

  // Telegram
  if (p.telegramChatId && p.notificationsTelegram !== false) {
    const r = await sendTelegram(p.telegramChatId, tgText);
    results.telegram = (r && r.ok) ? 'sent' : 'failed';
    if (!r || !r.ok) console.warn(`[CEE] Telegram failed for ${pid}:`, r && r.description);
  }

  // Email — open for all individual player events
  // Broadcast results to all players uses Telegram+Push only (no email there)
  if (p.email && p.notificationsEmail !== false) {
    const r = await sendEmail(p.email, subject, htmlBody);
    results.email = r.success ? 'sent' : 'failed';
    if (!r.success) console.warn(`[CEE] Email failed for ${pid}:`, r.error);
  }

  // Web Push — fire for every player who has subscribed, if they haven't disabled it
  if (p.pushSubscription && p.notificationsPush !== false) {
    let sub;
    try { sub = typeof p.pushSubscription === 'string' ? JSON.parse(p.pushSubscription) : p.pushSubscription; }
    catch(e) { sub = null; }
    if (sub) {
      // Strip HTML tags for the push body
      const pushBody = tgText.replace(/<[^>]+>/g, '').replace(/\n{3,}/g, '\n\n').trim();
      const r = await _sendWebPush(sub, {
        title:     '⚡ CEE — Campus eSports Elite',
        body:      pushBody.substring(0, 200),
        eventType,
        fixtureId: fixtureId || null,
        urgency:   ['CHECKIN_OPEN','CHECKIN_REMINDER_15M','CHECK_IN_NOW'].includes(eventType) ? 'high' : 'normal',
        data:      { url: `${process.env.SITE_URL || 'https://cee-esports.web.app'}#hub` }
      });
      results.push = r.ok ? 'sent' : 'failed';
      if (!r.ok) {
        console.warn(`[CEE] Web push failed for ${pid}:`, r.error);
        // If subscription expired/gone, clean it up from Firestore
        if (r.expired) {
          db.collection('players').doc(pid).update({ pushSubscription: admin.firestore.FieldValue.delete() }).catch(()=>{});
          console.log(`[CEE] Removed expired push subscription for ${pid}`);
        }
      }
    }
  }

  // WhatsApp relay — always queue if player has a number, regardless of other channels
  if (p.whatsappNumber) {
    await _queueWhatsAppRelay(fixtureId, pid, p, tgText);
    results.whatsapp = 'queued';
  }

  // Log the attempt — use actual delivery result, not assumed 'sent'
  const channelList = [
    results.telegram && 'telegram',
    results.email    && 'email',
    results.push     && 'push',
    results.whatsapp && 'whatsapp'
  ].filter(Boolean).join('+') || 'none';
  const actualStatus = (
    results.telegram === 'sent' || results.email === 'sent' ||
    results.push === 'sent' || results.whatsapp === 'queued'
  ) ? 'sent' : 'failed';

  await logNotif(fixtureId, pid, channelList, eventType, actualStatus, null, {
    messageText: tgText, emailSubject: subject,
    telegramChatId: p.telegramChatId || null, email: p.email || null,
    deliveryResults: results
  }).catch(() => {});

  return results;
}

async function _notifyBothReady(fix, fixtureId) {
  const tg   = `⚡ <b>BOTH PLAYERS READY!</b>\n\nYour match is now <b>IN PROGRESS</b>.\nPlay your game and submit your result screenshot via the Player Hub.\n\n<b>Deadline:</b> 5 hours from now (or 1 hour before window closes).`;
  const html = `<p>⚡ Both you and your opponent have clicked Ready!</p>
    <p>Your match is now <strong>IN PROGRESS</strong>. Play your game and submit your result screenshot from the Player Hub.</p>
    <div class="hl">Submission deadline: 5 hours from now (or 1 hour before the window closes)</div>`;
  await Promise.allSettled([
    _notifyPlayer(fix.playerAId, fixtureId, 'BOTH_READY', 'CEE — Match is Live! 🎮', html, tg),
    _notifyPlayer(fix.playerBId, fixtureId, 'BOTH_READY', 'CEE — Match is Live! 🎮', html, tg)
  ]);
}

async function _notifyPartnerReady(otherId, fix, fixtureId) {
  if (!otherId) return;
  const tg   = `⏳ <b>Your opponent is Ready!</b>\n\nLog in to the CEE Player Hub and click Ready to start your match.`;
  const html = `<p>⏳ Your opponent has clicked Ready for your upcoming fixture.</p>
    <p>Log in to the <strong>CEE Player Hub</strong> and click <strong>Ready</strong> to start the match.</p>`;
  await _notifyPlayer(otherId, fixtureId, 'PARTNER_READY', 'CEE — Opponent is Ready!', html, tg);
}

async function _sendMatchNotifications(type, fixtureId, playerAId, playerBId, seasonId) {
  const adminEmail = env.admin && env.admin.email;
  const adminChat  = env.telegram && env.telegram.admin_chat_id;

  const both = async (subj, html, tg) => Promise.allSettled([
    _notifyPlayer(playerAId, fixtureId, type, subj, html, tg),
    _notifyPlayer(playerBId, fixtureId, type, subj, html, tg)
  ]);

  if (type === 'WINDOW_OPEN') {
    await both(
      'CEE — Match Window Open! 🟢',
      `<p>🟢 Your match window is now <strong>OPEN</strong>!</p><p>Log in to the CEE Player Hub to propose a play time with your opponent.</p>`,
      `🟢 <b>Match window OPEN!</b>\n\nLog in to the CEE Player Hub to propose a match time with your opponent.\n🌐 ${process.env.SITE_URL || 'https://cee-esports.web.app'}`
    );
  }
  if (type === 'READY_REMINDER_1') {
    await both(
      'CEE — Match Window Reminder ⏰',
      `<p>⏰ Your match window has been open for a while, but no time has been agreed yet.</p><p>Log in to the CEE Player Hub and propose a match time with your opponent.</p>`,
      `⏰ <b>Reminder:</b> Your match window is open!\n\nYou haven't agreed on a time yet. Log in to the Player Hub and propose a time before the window closes.`
    );
  }
  if (type === 'READY_REMINDER_2') {
    await both(
      'CEE — Proposal Waiting for Response ⏳',
      `<p>⏳ A match time has been proposed but hasn't been responded to yet.</p><p>Log in to the CEE Player Hub to respond — you have limited time before the window closes.</p>`,
      `⏳ <b>Action required!</b>\n\nA match time proposal is waiting for your response on the CEE Player Hub. Please respond before the window closes!`
    );
  }
  if (type === 'DEADLINE_REMINDER') {
    await both(
      'CEE — 1 Hour Left in Match Window ⚠️',
      `<p>⚠️ <strong>1 hour remaining</strong> in your match window.</p><p>If no time is agreed and no result is submitted, the match will be voided. Log in now.</p>`,
      `⚠️ <b>1 hour left!</b>\n\nYour match window closes in about 1 hour. Log in to the Player Hub immediately to agree on a time or check in.`
    );
  }
  if (type === 'FORFEIT_APPLIED') {
    await both(
      'CEE — Forfeit Applied ⚠️',
      `<p>⚠️ A forfeit has been applied to your fixture because a player committed to a time and did not check in.</p><p>Check the CEE website for the final result.</p>`,
      `⚠️ <b>Forfeit applied to your fixture.</b>\n\nA player committed to a time and did not check in. Check the CEE website for the result.`
    );
    if (adminChat) await sendTelegram(adminChat, `⚠️ Forfeit applied to fixture ${fixtureId}`).catch(()=>{});
  }
  if (type === 'RESULT_PENDING') {
    if (adminEmail) await sendEmail(adminEmail, 'CEE — Result Awaiting Approval',
      `<p>A match result is ready for your review in the <strong>Result Queue</strong>.</p>
       <div class="hl">Fixture ID: ${fixtureId}</div>
       <p>Auto-approve triggers in 45 minutes if no action is taken.</p>`).catch(()=>{});
    if (adminChat) await sendTelegram(adminChat,
      `📋 <b>Result awaiting approval</b>\nFixture: ${fixtureId}\nAuto-approves in 45 minutes.`).catch(()=>{});
  }
  if (type === 'RESULT_APPROVED') {
    // Fetch fixture to get the actual score
    try {
      const fixSnap = await db.collection('fixtures').doc(fixtureId).get();
      const fix = fixSnap.exists ? fixSnap.data() : {};
      const hg = fix.playerAGoals ?? null, ag = fix.playerBGoals ?? null;
      const pAName = fix.playerAName || 'Player A';
      const pBName = fix.playerBName || 'Player B';
      const hasScore = hg !== null && ag !== null;
      const scoreLine = hasScore ? `${pAName} <strong>${hg} – ${ag}</strong> ${pBName}` : '';
      const scoreTg   = hasScore ? `${pAName} ${hg} – ${ag} ${pBName}` : '';

      const winnerA = hasScore && hg > ag, winnerB = hasScore && ag > hg, draw = hasScore && hg === ag;

      // Notify Player A with personalised outcome
      const outcomeA = winnerA ? '🏆 You won!' : winnerB ? '😔 You lost.' : draw ? '🤝 It\'s a draw.' : '';
      const htmlA = `<p>✅ Your match result has been <strong>approved</strong>!</p>${hasScore ? `<div class="hl"><strong>${scoreLine}</strong><br>${outcomeA}</div>` : ''}<p>Check the updated standings on the CEE website.</p>`;
      const tgA   = `✅ <b>Result approved!</b>\n\n${scoreTg ? scoreTg + '\n' + outcomeA + '\n' : ''}Check the updated standings on the CEE website.`;

      // Notify Player B with personalised outcome
      const outcomeB = winnerB ? '🏆 You won!' : winnerA ? '😔 You lost.' : draw ? '🤝 It\'s a draw.' : '';
      const htmlB = `<p>✅ Your match result has been <strong>approved</strong>!</p>${hasScore ? `<div class="hl"><strong>${scoreLine}</strong><br>${outcomeB}</div>` : ''}<p>Check the updated standings on the CEE website.</p>`;
      const tgB   = `✅ <b>Result approved!</b>\n\n${scoreTg ? scoreTg + '\n' + outcomeB + '\n' : ''}Check the updated standings on the CEE website.`;

      await Promise.allSettled([
        _notifyPlayer(playerAId, fixtureId, type, 'CEE — Result Approved ✅', htmlA, tgA),
        _notifyPlayer(playerBId, fixtureId, type, 'CEE — Result Approved ✅', htmlB, tgB)
      ]);
    } catch(e) {
      // Fallback to generic if fixture fetch fails
      await Promise.allSettled([
        _notifyPlayer(playerAId, fixtureId, type, 'CEE — Result Approved ✅', `<p>✅ Your match result has been <strong>approved</strong>!</p><p>Check the updated standings on the CEE website.</p>`, `✅ <b>Match result approved!</b>\nCheck the updated standings on the CEE website.`),
        _notifyPlayer(playerBId, fixtureId, type, 'CEE — Result Approved ✅', `<p>✅ Your match result has been <strong>approved</strong>!</p><p>Check the updated standings on the CEE website.</p>`, `✅ <b>Match result approved!</b>\nCheck the updated standings on the CEE website.`)
      ]);
    }
  }
  if (type === 'DISPUTE_OPENED') {
    await both(
      'CEE — Dispute Opened ⚖️',
      `<p>⚖️ A <strong>dispute</strong> has been opened for your match.</p><p>The admin will review screenshots and statements. Auto-resolves in 72 hours if admin takes no action.</p>`,
      `⚖️ <b>Dispute opened</b> for your fixture.\nAdmin will review. Auto-resolves in 72 hours.`
    );
    if (adminChat) await sendTelegram(adminChat, `⚖️ <b>Dispute opened</b>\nFixture: ${fixtureId}\nRequires review within 72 hours.`).catch(()=>{});
    if (adminEmail) await sendEmail(adminEmail, 'CEE — Dispute Opened',
      `<p>⚖️ A dispute has been opened for fixture <strong>${fixtureId}</strong>.</p>
       <p>Please review in the admin Disputes tab. Auto-resolves as 0–0 in 72 hours.</p>`).catch(()=>{});
  }
  if (type === 'DISPUTE_AUTO_RESOLVED') {
    await both(
      'CEE — Dispute Auto-Resolved ⚖️',
      `<p>⚖️ Your dispute has been <strong>auto-resolved as a 0–0 draw</strong> after 72 hours without admin action.</p><p>The final result has been recorded.</p>`,
      `⚖️ <b>Dispute auto-resolved</b> (72hr)\nResult: 0–0 draw. Check standings on the CEE website.`
    );
    if (adminChat) await sendTelegram(adminChat, `⚖️ <b>Dispute auto-resolved</b> (72hr)\nFixture: ${fixtureId}\nResult: 0–0 draw`).catch(()=>{});
  }
  if (type === 'REPLAY_SCHEDULED') {
    await both(
      'CEE — Replay Scheduled 🔄',
      `<p>🔄 A <strong>replay</strong> has been scheduled for your fixture.</p><p>Check the CEE Player Hub for the new match window details.</p>`,
      `🔄 <b>Replay scheduled</b>\nCheck the CEE Player Hub for your new match window.`
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL: Anti-cheat + Score cross-validation
// AC-1: Levenshtein similarity | COR-3: reversed perspective | AC-2: escalation
// ═══════════════════════════════════════════════════════════════════════════
function _stringSimilarity(a, b) {
  if (!a || !b) return 0;
  if (a === b) return 1;
  const la = a.length, lb = b.length, maxLen = Math.max(la, lb);
  if (maxLen === 0) return 1;
  const dp = Array.from({ length: la + 1 }, (_, i) => [i]);
  for (let j = 0; j <= lb; j++) dp[0][j] = j;
  for (let i = 1; i <= la; i++)
    for (let j = 1; j <= lb; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return 1 - dp[la][lb] / maxLen;
}
const CLUB_MATCH_THRESHOLD = 0.75;

async function _crossValidateScores(fixtureId, fix) {
  const fixRef = db.collection('fixtures').doc(fixtureId);
  const extA = fix.aiExtractedA || {}, extB = fix.aiExtractedB || {};
  const hA = extA.home, aA = extA.away, hB = extB.home, aB = extB.away;

  const scoresMatchDirect   = hA !== null && aA !== null && hB !== null && aB !== null && hA === hB && aA === aB;
  const scoresMatchReversed = hA !== null && aA !== null && hB !== null && aB !== null && hA === aB && aA === hB;
  const scoresMatch = scoresMatchDirect || scoresMatchReversed;

  if (scoresMatchReversed && !scoresMatchDirect) {
    await fixRef.update({ screenshotPerspectiveWarning: true });
    await audit('ANTICHEAT_PERSPECTIVE_WARN', fixtureId, 'fixture',
      `Reversed perspective: A=${hA}-${aA}, B=${hB}-${aB}`);
  }

  if (scoresMatch && Math.abs(hA - aA) >= 6) {
    await fixRef.update({ collusionFlagGD: true });
    await audit('ANTICHEAT_FLAG', fixtureId, 'fixture', `GD ≥ 6: ${hA}-${aA}`);
  }

  const [prevA, prevB] = await Promise.all([
    db.collection('fixtures').where('seasonId','==',fix.seasonId).where('status','==','approved')
      .where('playerAId','in',[fix.playerAId,fix.playerBId]).get(),
    db.collection('fixtures').where('seasonId','==',fix.seasonId).where('status','==','approved')
      .where('playerBId','in',[fix.playerAId,fix.playerBId]).get()
  ]);
  const seenIds = new Set(); let repeatCount = 0;
  [...prevA.docs, ...prevB.docs].forEach(d => {
    if (seenIds.has(d.id)) return; seenIds.add(d.id);
    const f = d.data();
    if ((f.playerAGoals === hA && f.playerBGoals === aA) ||
        (f.playerAGoals === aA && f.playerBGoals === hA)) repeatCount++;
  });
  if (scoresMatch && repeatCount >= 2) {
    await fixRef.update({ collusionFlagRepeat: true });
    await audit('ANTICHEAT_FLAG', fixtureId, 'fixture', `Repeated scoreline ${hA}-${aA} (${repeatCount}x)`);
  }

  // AC-2: escalate any collusion flag → screenshotFlaggedForReview
  const freshSnap = await fixRef.get();
  const fd = freshSnap.data() || {};
  const anyFlag = fd.collusionFlagTime || fd.collusionFlagRepeat || fd.collusionFlagGD;
  if (scoresMatch && anyFlag && !fd.screenshotFlaggedForReview) {
    await fixRef.update({ screenshotFlaggedForReview: true,
      screenshotFlagReason: 'Collusion flag raised — requires admin review before approval' });
    const adminChat = env.telegram && env.telegram.admin_chat_id;
    if (adminChat) {
      const flags = [fd.collusionFlagTime&&'timing',fd.collusionFlagRepeat&&'repeated scoreline',
                     fd.collusionFlagGD&&'goal difference'].filter(Boolean).join(', ');
      sendTelegram(adminChat,
        `🚨 <b>Collusion flag(s) raised</b>\nFixture: ${fixtureId}\nFlags: ${flags}\nWill NOT auto-approve.`
      ).catch(()=>{});
    }
    await audit('ANTICHEAT_ESCALATE', fixtureId, 'fixture', `Collusion flags: ${anyFlag}`);
  }

  if (!scoresMatch) {
    await fixRef.update({ status:'disputed', disputeOpenedAt: admin.firestore.FieldValue.serverTimestamp() });
    await db.collection('disputes').add({
      fixtureId, seasonId: fix.seasonId,
      playerAId: fix.playerAId, playerBId: fix.playerBId,
      scoreClaimedA: `${hA}-${aA}`, scoreClaimedB: `${hB}-${aB}`,
      screenshotUrlA: fix.playerAScreenshotUrl || null,
      screenshotUrlB: fix.playerBScreenshotUrl || null,
      status:'open', autoResolveAt: toTS(nowWAT().plus({ hours: 72 })),
      openedAt: admin.firestore.FieldValue.serverTimestamp(), verdict: null
    });
    await _sendMatchNotifications('DISPUTE_OPENED', fixtureId, fix.playerAId, fix.playerBId, fix.seasonId);
    return;
  }

  const autoApproveAt = toTS(nowWAT().plus({ minutes: 45 }));
  await fixRef.update({ status:'pending_approval', autoApproveAt, playerAGoals: hA, playerBGoals: aA, adminApproved: false });
  await _sendMatchNotifications('RESULT_PENDING', fixtureId, fix.playerAId, fix.playerBId, fix.seasonId);
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL: Swiss pairing
// ═══════════════════════════════════════════════════════════════════════════
function swissPair(standings, existingFixtures) {
  const paired = [], used = new Set();
  for (let i = 0; i < standings.length; i++) {
    if (used.has(standings[i].id)) continue;
    for (let j = i + 1; j < standings.length; j++) {
      if (used.has(standings[j].id)) continue;
      const played = existingFixtures.some(f =>
        (f.playerAId===standings[i].id && f.playerBId===standings[j].id) ||
        (f.playerAId===standings[j].id && f.playerBId===standings[i].id));
      if (!played) {
        paired.push({ a: standings[i].id, b: standings[j].id });
        used.add(standings[i].id); used.add(standings[j].id); break;
      }
    }
  }
  return paired;
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL: COR-1 H2H helpers — pre-built map prevents async in comparator
// ═══════════════════════════════════════════════════════════════════════════
function _buildH2HMap(fixtures) {
  const map = {};
  fixtures.forEach(f => {
    if (f.phase !== 'league' || !f.done) return;
    const [lo,hi] = f.playerAId < f.playerBId ? [f.playerAId,f.playerBId] : [f.playerBId,f.playerAId];
    const key = `${lo}__${hi}`;
    if (!map[key]) map[key] = { ptsLo:0, ptsHi:0 };
    const loIsA = f.playerAId === lo;
    const loG = loIsA ? f.playerAGoals : f.playerBGoals;
    const hiG = loIsA ? f.playerBGoals : f.playerAGoals;
    if (loG > hiG)      map[key].ptsLo += 3;
    else if (hiG > loG) map[key].ptsHi += 3;
    else { map[key].ptsLo += 1; map[key].ptsHi += 1; }
  });
  return map;
}
function _h2hFromMap(idA, idB, h2hMap) {
  const [lo,hi] = idA < idB ? [idA,idB] : [idB,idA];
  const e = h2hMap[`${lo}__${hi}`];
  if (!e) return 0;
  const ptsA = idA===lo ? e.ptsLo : e.ptsHi;
  const ptsB = idA===lo ? e.ptsHi : e.ptsLo;
  return ptsB - ptsA;
}
function _subGroupH2HOrder(group, fixtures, h2hMap) {
  if (group.length < 3) return null;
  const gids = new Set(group.map(s => s.id));
  const inFix = fixtures.filter(f => f.phase==='league' && f.done && gids.has(f.playerAId) && gids.has(f.playerBId));
  const subPts = {}, subGD = {};
  group.forEach(s => { subPts[s.id]=0; subGD[s.id]=0; });
  inFix.forEach(f => {
    const hg = f.playerAGoals||0, ag = f.playerBGoals||0;
    if (!f.isForfeit) { subGD[f.playerAId]=(subGD[f.playerAId]||0)+(hg-ag); subGD[f.playerBId]=(subGD[f.playerBId]||0)+(ag-hg); }
    if (hg > ag)      { subPts[f.playerAId]+=3; }
    else if (ag > hg) { subPts[f.playerBId]+=3; }
    else { subPts[f.playerAId]+=1; subPts[f.playerBId]+=1; }
  });
  return { subPts, subGD };
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL: _recalcStandingsInternal — COR-1/4 + PERF-1
// ═══════════════════════════════════════════════════════════════════════════
async function _recalcStandingsInternal(seasonId) {
  const players  = await getPlayers(seasonId);
  const fixtures = await getFixtures(seasonId);
  const approved = fixtures.filter(f => f.status==='approved' && f.adminApproved && f.phase==='league');

  const stats = {};
  players.forEach(p => { stats[p.id]={ id:p.id, clubName:p.clubName||'',
    pts:0, pld:0, w:0, d:0, l:0, gf:0, ga:0, gd:0, goals:0, forfeitWins:0 }; });

  approved.forEach(f => {
    const hg=f.playerAGoals||0, ag=f.playerBGoals||0;
    if (!stats[f.playerAId]||!stats[f.playerBId]) return;
    stats[f.playerAId].pld++; stats[f.playerBId].pld++;
    if (!f.isForfeit) {
      stats[f.playerAId].gf+=hg; stats[f.playerAId].ga+=ag; stats[f.playerAId].goals+=hg;
      stats[f.playerBId].gf+=ag; stats[f.playerBId].ga+=hg; stats[f.playerBId].goals+=ag;
    }
    if (hg > ag) {
      stats[f.playerAId].pts+=3; stats[f.playerAId].w++; stats[f.playerBId].l++;
      if (f.isForfeit) stats[f.playerAId].forfeitWins++;
    } else if (ag > hg) {
      stats[f.playerBId].pts+=3; stats[f.playerBId].w++; stats[f.playerAId].l++;
      if (f.isForfeit) stats[f.playerBId].forfeitWins++;
    } else { stats[f.playerAId].pts+=1; stats[f.playerAId].d++; stats[f.playerBId].pts+=1; stats[f.playerBId].d++; }
  });
  Object.values(stats).forEach(s => { s.gd = s.gf - s.ga; });

  const h2hMap = _buildH2HMap(approved);
  const pass1  = Object.values(stats).sort((a,b) => {
    if (b.pts!==a.pts) return b.pts-a.pts;
    if (b.gd !==a.gd)  return b.gd -a.gd;
    if (b.gf !==a.gf)  return b.gf -a.gf;
    return a.clubName.localeCompare(b.clubName);
  });

  const sorted = []; let i = 0;
  while (i < pass1.length) {
    let j = i+1;
    while (j<pass1.length && pass1[j].pts===pass1[i].pts && pass1[j].gd===pass1[i].gd && pass1[j].gf===pass1[i].gf) j++;
    const tg = pass1.slice(i,j);
    if (tg.length===1) { sorted.push(tg[0]); }
    else if (tg.length===2) {
      const [x,y]=tg, h=_h2hFromMap(x.id,y.id,h2hMap);
      if (h<0){sorted.push(x);sorted.push(y);} else if (h>0){sorted.push(y);sorted.push(x);} else {sorted.push(x);sorted.push(y);}
    } else {
      const sub=_subGroupH2HOrder(tg,approved,h2hMap);
      sorted.push(...tg.slice().sort((a,b)=>{
        if (!sub) return a.clubName.localeCompare(b.clubName);
        const pd=(sub.subPts[b.id]||0)-(sub.subPts[a.id]||0); if (pd!==0) return pd;
        const gd=(sub.subGD[b.id]||0)-(sub.subGD[a.id]||0);   if (gd!==0) return gd;
        return a.clubName.localeCompare(b.clubName);
      }));
    }
    i=j;
  }

  const batch = db.batch();
  sorted.forEach((s,idx) => {
    batch.update(db.collection('players').doc(s.id), {
      'stats.pts':s.pts,'stats.mp':s.pld,'stats.pld':s.pld,
      'stats.w':s.w,'stats.d':s.d,'stats.l':s.l,
      'stats.gf':s.gf,'stats.ga':s.ga,'stats.gd':s.gd,
      'stats.goals':s.goals,'stats.forfeitWins':s.forfeitWins, rank:idx+1
    });
  });
  batch.set(db.collection('standingsBroadcast').doc(seasonId),
    { standings:sorted, updatedAt:admin.firestore.FieldValue.serverTimestamp(), seasonId });
  batch.update(db.collection('seasons').doc(seasonId), { standingsDirty: false });
  await batch.commit();
  console.log(`[CEE] Standings recalculated: ${sorted.length} players`);

  // ── Tier Classification — runs after every standings recalculation ───────
  // Players need 4+ verified matches to qualify for a tier assignment.
  // PR (Performance Rating) is a weighted score across 6 dimensions.
  // Tiers are relative (top 20% = Elite, middle 60% = Mid, bottom 20% = Underdog)
  // so they self-calibrate as the season grows.
  try {
    await _recalculatePlayerTiers(seasonId, sorted);
  } catch(tierErr) { console.error('[CEE] Tier classification error:', tierErr.message); }

  // Background: refresh cached match probabilities after tiers update
  db.collection('config').doc('matchProbabilities').get()
    .then(d => {
      // Invalidate cache so next /getMatchProbabilities call recalculates fresh
      if (d.exists) return d.ref.update({ stale: true });
    }).catch(() => {});

  return sorted;
}

// ═══════════════════════════════════════════════════════════════════════════
// TIER CLASSIFICATION ENGINE — Performance Rating + Tier Assignment
// Runs after every standings recalculation. Requires 4+ verified matches.
// PR Formula (0–100 scale):
//   Win Rate          35% weight  — most important: winning is everything
//   GD per match      20% weight  — margin of victories and defeats
//   Shot accuracy     15% weight  — attacking efficiency
//   Pass accuracy     15% weight  — build-up quality
//   Goals scored/m   10% weight  — raw attacking output
//   Defensive record   5% weight  — clean sheets / goals conceded
// ═══════════════════════════════════════════════════════════════════════════
async function _recalculatePlayerTiers(seasonId, sortedStandings) {
  // Fetch matchStats for all players in this season
  const allMatchSnap = await db.collection('matchStats')
    .where('seasonId', '==', seasonId)
    .get();

  // Group by playerId
  const playerMatchMap = {};
  allMatchSnap.forEach(doc => {
    const d = doc.data();
    if (!playerMatchMap[d.playerId]) playerMatchMap[d.playerId] = [];
    playerMatchMap[d.playerId].push(d);
  });

  // Calculate PR for each player with 4+ matches
  const prScores = []; // { playerId, pr, matchCount }

  // Build player doc map for linkedPreviousPlayerIds lookup
  const playerDocMap = {};
  try {
    const plDocs = await db.collection('players').where('seasonId','==',seasonId).get();
    plDocs.forEach(d => { playerDocMap[d.id] = d.data(); });
  } catch(e) { /* non-fatal */ }

  for (const standing of sortedStandings) {
    const pid = standing.id;
    let matches = playerMatchMap[pid] || [];

    // Cross-season supplement: if sparse this season, add previous season matches at 60% weight
    if (matches.length < 6) {
      try {
        const pDoc = playerDocMap[pid] || {};
        const linkedIds = pDoc.linkedPreviousPlayerIds || [];
        if (linkedIds.length > 0) {
          const prevSnap = await db.collection('matchStats')
            .where('playerId', 'in', linkedIds.slice(0,10))
            .orderBy('verifiedAt', 'desc')
            .limit(10)
            .get();
          prevSnap.forEach(d => {
            matches = [...matches, { ...d.data(), _prevSeasonWeight: 0.6 }];
          });
        }
      } catch(e) { /* non-fatal */ }
    }

    if (matches.length < 4) continue; // Not enough data even after cross-season pull

    const n = matches.length;
    // Weight-aware counts: previous season matches count at 60%
    const weightedN    = matches.reduce((acc, m) => acc + (m._prevSeasonWeight || 1.0), 0);
    const wins         = matches.filter(m => m.result === 'W').length;
    const losses       = matches.filter(m => m.result === 'L').length;
    const weightedWins = matches.reduce((acc, m) => acc + (m.result === 'W' ? (m._prevSeasonWeight || 1.0) : 0), 0);

    // Win rate (0–100) — weight-adjusted
    const winRate = (weightedWins / weightedN) * 100;

    // GD per match — weight-adjusted (prev season matches at 60%)
    const totalGD = matches.reduce((acc, m) => acc + ((m.goalsFor || 0) - (m.goalsAgainst || 0)) * (m._prevSeasonWeight || 1.0), 0);
    const gdPerMatch = totalGD / weightedN;
    const gdScore = Math.max(0, Math.min(100, (gdPerMatch + 5) * 10)); // -5→0, 0→50, +5→100

    // Shot accuracy (shotsOnTarget / shots * 100), avg across matches with data
    const shotAccVals = matches
      .map(m => m.stats && m.stats.shots > 0 && m.stats.shotsOnTarget != null
        ? (m.stats.shotsOnTarget / m.stats.shots) * 100 : null)
      .filter(v => v !== null);
    const shotAcc = shotAccVals.length ? shotAccVals.reduce((a,b) => a+b, 0) / shotAccVals.length : 50;

    // Pass accuracy avg
    const passAccVals = matches
      .map(m => m.stats && m.stats.passes > 0 && m.stats.successfulPasses != null
        ? (m.stats.successfulPasses / m.stats.passes) * 100 : null)
      .filter(v => v !== null);
    const passAcc = passAccVals.length ? passAccVals.reduce((a,b) => a+b, 0) / passAccVals.length : 65;

    // Goals scored per match — weight-adjusted (cap at 5 = 100)
    const goalsPerMatch = matches.reduce((acc, m) => acc + (m.goalsFor || 0) * (m._prevSeasonWeight || 1.0), 0) / weightedN;
    const goalsScore = Math.min(100, (goalsPerMatch / 5) * 100);

    // Defensive record -- weight-adjusted (0 conceded = 100, 5+ = 0)
    const concededPerMatch = matches.reduce((acc, m) => acc + (m.goalsAgainst || 0) * (m._prevSeasonWeight || 1.0), 0) / weightedN;
    const defScore = Math.max(0, Math.min(100, (1 - concededPerMatch / 5) * 100));

    // Defensive activity -- tackles + interceptions combined, normalised to 0-100
    // 10+ combined per match = 100, 0 = 0. Rewards active defenders.
    const defActivityVals = matches.map(m => {
      const t = m.stats && m.stats.tackles       != null ? m.stats.tackles       : null;
      const i = m.stats && m.stats.interceptions != null ? m.stats.interceptions : null;
      if (t === null && i === null) return null;
      return (t || 0) + (i || 0);
    }).filter(v => v !== null);
    const defActivityAvg   = defActivityVals.length ? defActivityVals.reduce((a,b) => a+b,0) / defActivityVals.length : 5;
    const defActivityScore = Math.min(100, (defActivityAvg / 10) * 100);

    // Weighted PR (sums to 100%):
    //   Win rate 30% | GD/match 20% | Shot acc 15% | Pass acc 12%
    //   Goals/match 8% | Def record 5% | Def activity 10%
    const pr = Math.round(
      winRate          * 0.30 +
      gdScore          * 0.20 +
      shotAcc          * 0.15 +
      passAcc          * 0.12 +
      goalsScore       * 0.08 +
      defScore         * 0.05 +
      defActivityScore * 0.10
    );

    prScores.push({ playerId: pid, pr, matchCount: n, winRate: Math.round(winRate), gdPerMatch: Math.round(gdPerMatch * 10) / 10 });
  }

  if (prScores.length === 0) {
    console.log('[CEE] Tier classification: no players with 4+ matches yet');
    return;
  }

  // Assign tiers based on relative rank within qualified players
  prScores.sort((a, b) => b.pr - a.pr);
  const total = prScores.length;
  const eliteCutoff = Math.ceil(total * 0.20);   // Top 20%
  const midCutoff   = Math.ceil(total * 0.80);   // Top 80% (i.e. not bottom 20%)

  const batch = db.batch();
  prScores.forEach((p, idx) => {
    let tier = 'mid';
    if (idx < eliteCutoff)       tier = 'elite';
    else if (idx >= midCutoff)   tier = 'underdog';

    batch.update(db.collection('players').doc(p.playerId), {
      performanceRating: p.pr,
      playerTier: tier,
      tierUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
      tierMatchCount: p.matchCount
    });
  });

  // Write tier summary to config for frontend to read
  const tierSummary = {
    seasonId,
    totalRanked: total,
    eliteThresholdPR: prScores[eliteCutoff - 1]?.pr || 0,
    midThresholdPR:   prScores[midCutoff - 1]?.pr   || 0,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };
  batch.set(db.collection('config').doc('tierSummary'), tierSummary);

  await batch.commit();
  console.log(`[CEE] Tiers assigned: ${prScores.filter((_,i) => i < eliteCutoff).length} Elite, ${prScores.filter((_,i) => i >= eliteCutoff && i < midCutoff).length} Mid, ${prScores.filter((_,i) => i >= midCutoff).length} Underdog (${total} total ranked)`);
}

// ═══════════════════════════════════════════════════════════════════════════
// PLAYER INTEGRITY SCORE ENGINE
// Tracks cumulative fraud signal pattern per player across all submissions.
// No single submission blocks a player unfairly -- pattern must accumulate.
// Score: starts 100. Hard flag -15, soft flag -3, clean submission +1.
// Score < 70: admin alerted, enhanced review flagged on future submissions.
// Score < 50: player auto-blocked pending admin review.
// ═══════════════════════════════════════════════════════════════════════════
async function _updatePlayerIntegrityScore(playerId, type) {
  try {
    const pd = await db.collection('players').doc(playerId).get();
    if (!pd.exists) return;
    const p = pd.data();
    const current = p.integrityScore != null ? p.integrityScore : 100;
    let delta = 0;
    if (type === 'hard_flag') delta = -15;
    else if (type === 'soft_flag') delta = -3;
    else if (type === 'clean') delta = 1;
    const newScore = Math.max(0, Math.min(100, current + delta));
    const update = { integrityScore: newScore, integrityLastUpdated: admin.firestore.FieldValue.serverTimestamp() };
    const adminChat = env.telegram && env.telegram.admin_chat_id;
    // Auto-block when score first drops below 50
    if (newScore < 50 && current >= 50) {
      update.hubBlocked = true;
      update.hubBlockedReason = `Integrity score ${newScore}/100 -- auto-suspended pending admin review`;
      update.hubBlockedAt = admin.firestore.FieldValue.serverTimestamp();
      if (adminChat) sendTelegram(adminChat,
        `PLAYER AUTO-SUSPENDED (Integrity)\nPlayer: ${playerId}\nClub: ${p.clubName||'?'}\nScore: ${newScore}/100\nPattern of fraud flags triggered suspension. Review in admin panel.`
      ).catch(()=>{});
      await audit('INTEGRITY_AUTO_BLOCK', playerId, 'player', `Integrity score ${newScore} -- auto-suspended`);
    }
    // Warn admin when score first drops below 70
    if (newScore < 70 && current >= 70) {
      if (adminChat) sendTelegram(adminChat,
        `INTEGRITY WARNING\nPlayer: ${p.clubName||playerId}\nScore dropped to ${newScore}/100 -- enhanced review now active.`
      ).catch(()=>{});
    }
    await db.collection('players').doc(playerId).update(update);
    console.log(`[CEE] Integrity: ${playerId} ${current} -> ${newScore} (${type})`);
  } catch(e) { console.error('[CEE] _updatePlayerIntegrityScore error:', e.message); }
}


// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL: _checkKnockoutQualification — Auto-12/17
// ═══════════════════════════════════════════════════════════════════════════
async function _checkKnockoutQualification(seasonId) {
  const seasonDoc = await db.collection('seasons').doc(seasonId).get();
  if (!seasonDoc.exists) return;
  const season = seasonDoc.data();
  if (season.leagueFrozen || season.knockoutGenerated) return;

  const fixtures  = await getFixtures(seasonId);
  const leagueFix = fixtures.filter(f => f.phase==='league'||!f.phase);
  if (leagueFix.length===0 || !leagueFix.every(f => f.done)) return;

  await seasonDoc.ref.update({ leagueFrozen: true });

  const players = await getPlayers(seasonId);
  const fmt     = season.format || 20;
  const cfg20   = { autoQual:4,  playoffEnd:12 };
  const cfg28   = { autoQual:8,  playoffEnd:24 };
  const cfg36   = { autoQual:8,  playoffEnd:24 };
  const koCfg   = fmt>=36 ? cfg36 : fmt>=28 ? cfg28 : cfg20;

  const sorted  = players.sort((a,b) => (a.rank||99)-(b.rank||99));
  const batch   = db.batch(); const notifys = [];

  sorted.forEach((p,idx) => {
    const rank = idx+1;
    const koStatus = rank<=koCfg.autoQual ? 'auto_qualified' : rank<=koCfg.playoffEnd ? 'playoff' : 'eliminated';
    batch.update(db.collection('players').doc(p.id), { knockoutStatus:koStatus, knockoutRank:rank });
    notifys.push({ playerId:p.id, status:koStatus });
  });
  batch.update(seasonDoc.ref, { knockoutGenerated:true, leagueEndedAt:admin.firestore.FieldValue.serverTimestamp() });

  const playoffPlayers = sorted.filter((_,i) => i>=koCfg.autoQual && i<koCfg.playoffEnd);
  const halfLen        = Math.floor(playoffPlayers.length/2);
  const now            = nowWAT(); let pd2 = now.plus({days:1});
  while (![5,6,7].includes(pd2.weekday)) pd2 = pd2.plus({days:1});
  const poOpenH  = pd2.weekday===5 ? 15 : 13;
  const poOpen   = pd2.set({hour:poOpenH,minute:0,second:0,millisecond:0});
  const poClose  = pd2.set({hour:23,minute:59,second:59,millisecond:0});
  const fixBatch = db.batch();
  for (let i=0; i<halfLen; i++) {
    const top=playoffPlayers[i], bot=playoffPlayers[playoffPlayers.length-1-i];
    fixBatch.set(db.collection('fixtures').doc(), {
      seasonId, phase:'playoff', playerAId:top.id, playerBId:bot.id,
      playerAName:top.clubName||top.gameName||'', playerBName:bot.clubName||bot.gameName||'',
      playerALeagueRank:top.knockoutRank||(i+koCfg.autoQual+1),
      playerBLeagueRank:bot.knockoutRank||(koCfg.playoffEnd-i),
      status:'scheduled', windowOpenTime:toTS(poOpen), windowCloseTime:toTS(poClose),
      matchday:0.1+i*0.001, week:0, done:false, adminApproved:false,
      createdAt:admin.firestore.FieldValue.serverTimestamp()
    });
  }

  await batch.commit(); await fixBatch.commit();
  console.log(`[CEE] Generated ${halfLen} playoff fixtures for season ${seasonId}`);

  await Promise.allSettled(notifys.map(async n => {
    const pd = await db.collection('players').doc(n.playerId).get();
    if (!pd.exists) return;
    const p = pd.data();
    const statusMap = {
      auto_qualified:{ label:'🏆 AUTO-QUALIFIED', detail:'You have qualified directly for the knockout round!', type:'KNOCKOUT_QUALIFIED' },
      playoff:       { label:'⚔️ PLAYOFF BOUND',  detail:'You will compete in the playoff round to qualify for the knockout.', type:'KNOCKOUT_PLAYOFF' },
      eliminated:    { label:'❌ ELIMINATED',      detail:'You did not qualify for the knockout round. Better luck next season!', type:'KNOCKOUT_ELIMINATED' }
    };
    const info = statusMap[n.status];
    const sends = [];
    if (p.email) sends.push(sendEmail(p.email,`CEE — League Phase Complete: ${info.label}`,
      `<p>The league phase is complete! Your final status:</p>
       <div class="hl" style="font-size:18px;font-weight:700">${info.label}</div>
       <p>${info.detail}</p>`).catch(()=>{}));
    if (p.telegramChatId) sends.push(sendTelegram(p.telegramChatId,`${info.label}\n\n${info.detail}`).catch(()=>{}));
    sends.push(logNotif(null,n.playerId,'both',info.type,'sent').catch(()=>{}));
    return Promise.allSettled(sends);
  }));

  const adminEmail=env.admin&&env.admin.email, adminChat=env.telegram&&env.telegram.admin_chat_id;
  if (adminEmail) await sendEmail(adminEmail,'CEE — League Phase Complete!',
    `<p>🏆 All league fixtures done for season <strong>${seasonId}</strong>.</p>
     <ul>
       <li>Auto-qualified: ${sorted.filter((_,i)=>i<koCfg.autoQual).map(p=>p.clubName).join(', ')}</li>
       <li>Playoff: ${sorted.filter((_,i)=>i>=koCfg.autoQual&&i<koCfg.playoffEnd).length} players</li>
       <li>Eliminated: ${sorted.filter((_,i)=>i>=koCfg.playoffEnd).length} players</li>
     </ul>`);
  if (adminChat) await sendTelegram(adminChat,`🏆 <b>League phase complete!</b>\nSeason: ${seasonId}`);
  await audit('LEAGUE_PHASE_COMPLETE',seasonId,'season',`${sorted.length} players notified`);
}

// ═══════════════════════════════════════════════════════════════════════════
// INTERNAL: _generateWeekFixtures
// ═══════════════════════════════════════════════════════════════════════════
async function _generateWeekFixtures(seasonId, week, players, pairs, season) {
  const now = nowWAT(); let weekStart = now.plus({days:1});
  while (weekStart.weekday!==5) weekStart=weekStart.plus({days:1});
  const slots=[
    {day:weekStart,              openH:15, md:(week-1)*3+1},
    {day:weekStart.plus({days:1}),openH:13, md:(week-1)*3+2},
    {day:weekStart.plus({days:2}),openH:13, md:(week-1)*3+3}
  ];
  if (pairs.length===0) {
    for (let i=0; i+1<players.length; i+=2)
      pairs.push({ a:players[i].id, b:players[i+1].id });
  }
  const batch = db.batch();
  pairs.forEach((pair,idx) => {
    const slot=slots[idx%3];
    const winOpen =slot.day.set({hour:slot.openH,minute:0,second:0,millisecond:0});
    const winClose=slot.day.set({hour:23,minute:59,second:59,millisecond:0});
    batch.set(db.collection('fixtures').doc(), {
      seasonId, phase:'league', playerAId:pair.a, playerBId:pair.b,
      week, matchday:slot.md, status:'scheduled',
      windowOpenTime:toTS(winOpen), windowCloseTime:toTS(winClose),
      createdAt:admin.firestore.FieldValue.serverTimestamp(),
      done:false, adminApproved:false
    });
  });
  await batch.commit();
}

// ═══════════════════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════════════════
app.get('/', (req, res) => res.json({ status:'ok', service:'CEE Backend v2.0 (Railway)' }));
app.get('/health', (req, res) => res.json({ status:'ok', ts: Date.now() }));

// ═══════════════════════════════════════════════════════════════════════════
// POST /verifyAdminSecret — verifies the x-cee-admin-secret header
// This is the ONLY endpoint the admin login flow should use to check credentials.
// Returns 200 + { ok:true } if correct, 403 if wrong, 503 if not configured.
// ═══════════════════════════════════════════════════════════════════════════
app.post('/verifyAdminSecret', (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  return res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /verifyPlayerPin — SEC-1: direct equality queries, LOCKOUT-01
// ═══════════════════════════════════════════════════════════════════════════
app.post('/verifyPlayerPin', async (req, res) => {
  const { tag, pin, seasonId } = req.body;
  if (!tag||!pin||!seasonId) return res.status(400).json({ success:false, message:'Missing fields' });
  try {
    const tagUpper=tag.toUpperCase();
    let player=null;
    const byGameName=await db.collection('players').where('seasonId','==',seasonId).where('gameName','==',tagUpper).limit(1).get();
    if (!byGameName.empty){const d=byGameName.docs[0];player={id:d.id,...d.data()};}
    if (!player){const byClub=await db.collection('players').where('seasonId','==',seasonId).where('clubName','==',tagUpper).limit(1).get();
      if(!byClub.empty){const d=byClub.docs[0];player={id:d.id,...d.data()};}}
    if (!player){const byIni=await db.collection('players').where('seasonId','==',seasonId).where('initials','==',tagUpper).limit(1).get();
      if(!byIni.empty){const d=byIni.docs[0];player={id:d.id,...d.data()};}}
    if (!player) {
      // Check if this tag exists in a previous season — helpful hint for returning players
      try {
        const prevSnap = await db.collection('players')
          .where('gameName', '==', tagUpper)
          .limit(1).get();
        const prevByClub = prevSnap.empty
          ? await db.collection('players').where('clubName', '==', tagUpper).limit(1).get()
          : null;
        const foundPrev = !prevSnap.empty || (prevByClub && !prevByClub.empty);
        if (foundPrev) {
          return res.json({
            success: false,
            message: 'Tag found in a previous season but not this one. If you played before, re-register for this season and your history will carry over automatically.'
          });
        }
      } catch(e) { /* non-fatal */ }
      return res.json({ success:false, message:'Player not found. Check your gaming tag.' });
    }

    // Check if player is blocked (integrity/admin block)
    if (player.hubBlocked) {
      return res.json({ success:false, blocked:true, message:'Your hub access has been suspended. Contact the league admin.' });
    }
    // Check permanent PIN block (too many lockouts — requires payment or admin)
    const secretDocPre=await db.collection('playerSecrets').doc(player.id).get();
    if (secretDocPre.exists && secretDocPre.data().pinPermanentBlock) {
      return res.json({ success:false, permanentBlock:true, playerId:player.id,
        message:'Account permanently locked. Pay ₦300 to unlock or contact admin.' });
    }

    const secretDoc=await db.collection('playerSecrets').doc(player.id).get();
    const secrets=secretDoc.exists?secretDoc.data():{};
    const {pinHash,pinLockoutUntil,pinFailAttempts}=secrets;
    if (!pinHash) return res.json({ success:false, message:'No PIN set. Contact admin.' });

    if (pinLockoutUntil) {
      const lockUntil=fromTS(pinLockoutUntil);
      if (nowWAT()<lockUntil) {
        const minLeft=Math.ceil(lockUntil.diff(nowWAT(),'minutes').minutes);
        return res.json({ success:false, locked:true, message:`Too many attempts. Try again in ${minLeft} minute(s).` });
      }
    }

    const match=await bcrypt.compare(pin,pinHash);
    if (!match) {
      const attempts=(pinFailAttempts||0)+1;
      const upd={ pinFailAttempts:attempts };
      if (attempts>=4) {
        const lockCount=(secrets.pinLockoutCount||0)+1;
        upd.pinLockoutCount=lockCount;
        upd.pinFailAttempts=0;
        if (lockCount>=2) {
          // Second+ lockout — permanently blocked until ₦300 paid or admin unblocks
          upd.pinPermanentBlock=true;
          upd.pinPermanentBlockAt=admin.firestore.FieldValue.serverTimestamp();
          await db.collection('playerSecrets').doc(player.id).update(upd);
          const adminChat=env.telegram&&env.telegram.admin_chat_id;
          if (adminChat) sendTelegram(adminChat,
            `🚫 <b>PIN Permanent Block</b>\nPlayer: ${player.clubName||player.gameName}\nLocked ${lockCount}x — requires ₦300 unlock or admin action.`
          ).catch(()=>{});
          return res.json({ success:false, permanentBlock:true, playerId:player.id,
            message:'Account permanently locked after repeated failed attempts. Pay ₦300 to unlock or contact admin.' });
        } else {
          // First lockout — 3hr free cooldown
          upd.pinLockoutUntil=toTS(nowWAT().plus({hours:3}));
          await db.collection('playerSecrets').doc(player.id).update(upd);
          const adminChat=env.telegram&&env.telegram.admin_chat_id;
          if (adminChat) sendTelegram(adminChat,
            `🔐 <b>PIN Lockout</b>\nPlayer: ${player.clubName||player.gameName}\nFirst lockout — 3hr free cooldown.`
          ).catch(()=>{});
          return res.json({ success:false, locked:true, message:'Too many failed attempts. Account locked for 3 hours. Try again later.' });
        }
      }
      await db.collection('playerSecrets').doc(player.id).update(upd);
      const remaining=Math.max(0,4-attempts);
      return res.json({ success:false, message:`Incorrect PIN. ${remaining} attempt(s) remaining.` });
    }

    await db.collection('playerSecrets').doc(player.id).update({ pinFailAttempts:0, pinLockoutUntil:null });
    const { email:_e, ...safePlayer } = player;
    return res.json({ success:true, player:safePlayer });
  } catch(e) { console.error('[CEE] verifyPlayerPin:',e); return res.status(500).json({ success:false, message:'Server error' }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /generateOtp — rate-limited 3/hr per player+purpose
// ═══════════════════════════════════════════════════════════════════════════
app.post('/generateOtp', async (req, res) => {
  const { playerId, fixtureId, purpose } = req.body;
  if (!playerId||!purpose) return res.status(400).json({ success:false, message:'Missing fields' });
  try {
    const pd=await db.collection('players').doc(playerId).get();
    if (!pd.exists) return res.json({ success:false, message:'Player not found' });
    const player=pd.data();
    if (!player.email) return res.json({ success:false, message:'No email on record. Contact admin.' });

    const oneHourAgo=toTS(nowWAT().minus({hours:1}));
    const recent=await db.collection('otpCodes')
      .where('playerId','==',playerId).where('purpose','==',purpose)
      .where('createdAt','>',oneHourAgo).get();
    if (recent.size>=3) return res.json({ success:false, message:'OTP limit reached (3 per hour). Please wait before requesting again.' });

    const otp=String(Math.floor(100000+Math.random()*900000));
    const codeHash=await bcrypt.hash(otp,12);
    await db.collection('otpCodes').add({
      playerId, codeHash, purpose, fixtureId:fixtureId||null,
      createdAt:admin.firestore.FieldValue.serverTimestamp(),
      expiresAt:toTS(nowWAT().plus({minutes:10})), used:false
    });
    const label=purpose==='ready'?'Mark Ready':'Submit Score';
    await sendEmail(player.email,`CEE — Your ${label} OTP`,
      `<p>Your one-time code for <strong>${label}</strong>:</p>
       <div class="hl" style="font-size:28px;font-weight:700;letter-spacing:.25em;text-align:center">${otp}</div>
       <p>Expires in <strong>10 minutes</strong>. Single use only.</p>
       <p>If you did not request this, ignore this email.</p>`);
    return res.json({ success:true, message:'OTP sent to your registered email.' });
  } catch(e) { console.error('[CEE] generateOtp:',e); return res.status(500).json({ success:false, message:'Server error' }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /confirmReady — validates OTP, marks player ready, sets submissionDeadline
// ═══════════════════════════════════════════════════════════════════════════
app.post('/confirmReady', async (req, res) => {
  const { playerId, fixtureId, otp, isHome } = req.body;
  if (!playerId||!fixtureId||!otp) return res.status(400).json({ success:false, message:'Missing fields' });
  try {
    const otpSnap=await db.collection('otpCodes')
      .where('playerId','==',playerId).where('fixtureId','==',fixtureId)
      .where('purpose','==','ready').where('used','==',false)
      .orderBy('createdAt','desc').limit(1).get();
    if (otpSnap.empty) return res.json({ success:false, message:'No valid OTP found. Request a new one.' });
    const otpDoc=otpSnap.docs[0], otpData=otpDoc.data();
    if (nowWAT()>fromTS(otpData.expiresAt)) return res.json({ success:false, message:'OTP expired. Request a new one.' });
    if (!(await bcrypt.compare(otp,otpData.codeHash))) return res.json({ success:false, message:'Invalid OTP.' });
    await otpDoc.ref.update({ used:true });

    const fixRef=db.collection('fixtures').doc(fixtureId);
    const fixSnap=await fixRef.get();
    if (!fixSnap.exists) return res.json({ success:false, message:'Fixture not found.' });
    const fix=fixSnap.data();

    if (fix.seasonId) {
      const sd=await db.collection('seasons').doc(fix.seasonId).get();
      if (sd.exists&&sd.data().forceMajeure) return res.json({ success:false, message:'Force Majeure active — windows paused.' });
    }

    const readyField=isHome?'playerAReadyAt':'playerBReadyAt';
    const otherReady=isHome?fix.playerBReadyAt:fix.playerAReadyAt;
    const update={ [readyField]:admin.firestore.FieldValue.serverTimestamp(), status:'ready_pending' };

    if (otherReady) {
      const bothAt=new Date();
      const winClose=fix.windowCloseTime?fix.windowCloseTime.toDate():new Date(bothAt.getTime()+8*3600000);
      const fiveHrs=new Date(bothAt.getTime()+5*3600*1000);
      const oneHrBuf=new Date(winClose.getTime()-3600*1000);
      update.bothReadyAt=admin.firestore.Timestamp.fromDate(bothAt);
      update.submissionDeadline=admin.firestore.Timestamp.fromDate(fiveHrs<oneHrBuf?fiveHrs:oneHrBuf);
      update.status='in_progress';
      await _notifyBothReady(fix,fixtureId);
    } else {
      await _notifyPartnerReady(isHome?fix.playerBId:fix.playerAId,fix,fixtureId);
    }
    await fixRef.update(update);
    return res.json({ success:true, message:'You are marked as Ready!' });
  } catch(e) { console.error('[CEE] confirmReady:',e); return res.status(500).json({ success:false, message:'Server error' }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// MATCH TIME AGREEMENT — replaces the "click ready and hope" system
//
// Flow:
//   window_open → either player proposes 1–3 time slots
//   → opponent accepts one slot → time_agreed
//   → at agreed time a 20-min check-in window opens → checkin_open
//   → both check in → in_progress → submit scores (unchanged from here)
//   → one no-show → forfeit (they committed to this time)
//   → neither checked in → void (0-0 DNP, no forfeit)
//   → no agreement after 2 proposal rounds → admin arbitration
//   → no proposal at all when window closes → void (no forfeit)
//
// Window durations (WAT):
//   Friday : 9 hrs open, proposable slots cover first 7 hrs (2 hr play buffer)
//   Sat/Sun: 11 hrs open, proposable slots cover first 9 hrs (2 hr play buffer)
// ═══════════════════════════════════════════════════════════════════════════

// Helper — generate 30-min slot list for a window
function _generateSlots(windowOpenTime, windowCloseTime) {
  const open  = fromTS(windowOpenTime);
  const close = fromTS(windowCloseTime);
  const bufferMins = 120; // always leave 2 hrs at end to actually play
  const slots = [];
  let cursor = open.plus({ minutes: 30 }); // earliest slot is 30 min after window opens
  while (cursor.plus({ minutes: bufferMins }) <= close) {
    slots.push(cursor.toJSDate());
    cursor = cursor.plus({ minutes: 30 });
  }
  return slots;
}

// Helper — notify a player about a proposal event
async function _notifyProposal(type, targetPlayerId, fixtureId, extraData = {}) {
  const adminChat = env.telegram && env.telegram.admin_chat_id;

  const fmtTime = ts => {
    if (!ts) return '?';
    const d = ts.toDate ? ts.toDate() : new Date(ts);
    return new Intl.DateTimeFormat('en-NG', {
      timeZone:'Africa/Lagos', weekday:'short', hour:'2-digit', minute:'2-digit', hour12:true
    }).format(d);
  };

  const msgs = {
    TIME_PROPOSED: {
      sub: 'CEE — Match Time Proposed ⏰',
      tg:  `⏰ <b>Match Time Proposed</b>\n\n${extraData.fromName||'Your opponent'} wants to play at:\n${(extraData.slots||[]).map((s,i)=>`  ${i+1}. ${fmtTime(s)}`).join('\n')}\n\nLog in to the CEE Player Hub to accept or counter-propose.`,
      html:`<p>⏰ <strong>${extraData.fromName||'Your opponent'}</strong> has proposed match times:</p><ul>${(extraData.slots||[]).map(s=>`<li>${fmtTime(s)}</li>`).join('')}</ul><p>Log in to the <strong>CEE Player Hub</strong> to accept one or suggest your own times.</p>`
    },
    TIME_ACCEPTED: {
      sub: 'CEE — Match Time Confirmed ✅',
      tg:  `✅ <b>Match Time Confirmed!</b>\n\nYour match is set for <b>${fmtTime(extraData.agreedSlot)}</b>.\n\nYou'll get a reminder 1 hour before. Log in to the CEE Player Hub at that time and click Check In.`,
      html:`<p>✅ Match time confirmed: <strong>${fmtTime(extraData.agreedSlot)}</strong></p><p>You'll receive a reminder 1 hour before. Log into the CEE Player Hub at that time and click <strong>Check In</strong> to start the match.</p>`
    },
    TIME_COUNTER_PROPOSED: {
      sub: 'CEE — Counter-Proposal Received 🔄',
      tg:  `🔄 <b>Counter-Proposal</b>\n\n${extraData.fromName||'Your opponent'} suggests:\n${(extraData.slots||[]).map((s,i)=>`  ${i+1}. ${fmtTime(s)}`).join('\n')}\n\nLog in to the CEE Player Hub to respond.`,
      html:`<p>🔄 <strong>${extraData.fromName||'Your opponent'}</strong> has counter-proposed:</p><ul>${(extraData.slots||[]).map(s=>`<li>${fmtTime(s)}</li>`).join('')}</ul><p>Log in to the <strong>CEE Player Hub</strong> to accept or make a final proposal.</p>`
    },
    CHECKIN_REMINDER_1H: {
      sub: 'CEE — Match in 1 Hour ⚡',
      tg:  `⚡ <b>Match in 1 hour!</b>\n\nAgreed time: <b>${fmtTime(extraData.agreedSlot)}</b>.\n\nMake sure you're free and ready. Click Check In on the CEE Player Hub when the time arrives.`,
      html:`<p>⚡ Your match is in <strong>1 hour</strong> — agreed time: <strong>${fmtTime(extraData.agreedSlot)}</strong></p><p>Be ready on the CEE Player Hub to click Check In.</p>`
    },
    CHECKIN_REMINDER_15M: {
      sub: 'CEE — Match Starting Soon! 🎮',
      tg:  `🎮 <b>Match in 15 minutes!</b>\n\nGet your console ready. The Check In button goes live at <b>${fmtTime(extraData.agreedSlot)}</b> on the CEE Player Hub.`,
      html:`<p>🎮 <strong>15 minutes</strong> until your match! Get your console ready.</p><p>The Check In button goes live at <strong>${fmtTime(extraData.agreedSlot)}</strong>.</p>`
    },
    CHECKIN_OPEN: {
      sub: 'CEE — Check In NOW! 🟢',
      tg:  `🟢 <b>CHECK IN NOW!</b>\n\nYour agreed match time is here. Log in to the CEE Player Hub and tap <b>Check In</b> within the next 20 minutes or the match may be forfeited.`,
      html:`<p>🟢 <strong>Your match time is NOW!</strong> Log into the CEE Player Hub and click <strong>Check In</strong> within the next 20 minutes.</p>`
    },
    ADMIN_ARBITRATION: {
      sub: 'CEE — Match Scheduling: Admin Review Needed',
      tg:  `⚖️ <b>Admin arbitration triggered</b>\n\nFixture ${fixtureId} — players could not agree on a match time after 2 proposal rounds.\n\nPlease review and assign a time manually in the admin panel.`,
      html: `<p>⚖️ Fixture <strong>${fixtureId}</strong> needs admin arbitration. Players exhausted 2 proposal rounds without agreeing.</p><p>Please log in to the admin panel and assign a match time manually.</p>`
    }
  };

  const m = msgs[type];
  if (!m) return;

  // Admin-only event
  if (type === 'ADMIN_ARBITRATION') {
    if (adminChat) await sendTelegram(adminChat, m.tg).catch(()=>{});
    const adminEmail = env.admin && env.admin.email;
    if (adminEmail && m.html) await sendEmail(adminEmail, m.sub, m.html).catch(()=>{});
    return;
  }

  // Player notification — goes through all channels they have
  await _notifyPlayer(targetPlayerId, fixtureId, type, m.sub, m.html, m.tg);
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /proposeMatchTime
// ─────────────────────────────────────────────────────────────────────────────
app.post('/proposeMatchTime', async (req, res) => {
  const { playerId, fixtureId, slots } = req.body;
  if (!playerId || !fixtureId || !Array.isArray(slots) || !slots.length || slots.length > 3)
    return res.status(400).json({ success:false, message:'Provide 1–3 time slots.' });

  try {
    const fixRef  = db.collection('fixtures').doc(fixtureId);
    const fixSnap = await fixRef.get();
    if (!fixSnap.exists) return res.json({ success:false, message:'Fixture not found.' });
    const fix = fixSnap.data();

    if (fix.seasonId) {
      const sd = await db.collection('seasons').doc(fix.seasonId).get();
      if (sd.exists && sd.data().forceMajeure)
        return res.json({ success:false, message:'Force Majeure active — match scheduling paused.' });
    }

    const allowed = ['window_open','awaiting_proposal','proposal_pending'];
    if (!allowed.includes(fix.status))
      return res.json({ success:false, message:'Cannot propose a time for this fixture right now.' });

    // Validate all slots are within the window and before the buffer cutoff
    const winOpen  = fix.windowOpenTime  ? fromTS(fix.windowOpenTime)  : null;
    const winClose = fix.windowCloseTime ? fromTS(fix.windowCloseTime) : null;
    const bufferCutoff = winClose ? winClose.minus({ minutes: 120 }) : null;

    const slotTs = slots.map(s => {
      const d = new Date(s);
      if (isNaN(d.getTime())) throw new Error('Invalid slot timestamp: ' + s);
      return admin.firestore.Timestamp.fromDate(d);
    });

    if (bufferCutoff) {
      for (const ts of slotTs) {
        const slotDt = fromTS(ts);
        if (winOpen && slotDt <= winOpen)
          return res.json({ success:false, message:'Slot must be after the window opens.' });
        if (slotDt > bufferCutoff)
          return res.json({ success:false, message:'Slot must be at least 2 hours before the window closes.' });
      }
    }

    const isHome = fix.playerAId === playerId;
    if (!isHome && fix.playerBId !== playerId)
      return res.json({ success:false, message:'You are not a participant in this fixture.' });

    const currentRound = fix.proposalRound || 0;
    const newRound     = currentRound + 1;

    if (newRound > 2) {
      return res.json({ success:false, message:'Maximum proposal rounds reached. Admin has been notified to arbitrate.' });
    }

    // If this is a counter-proposal, the OTHER player must have been the last proposer
    if (currentRound === 1 && fix.activeProposal && fix.activeProposal.fromPlayerId === playerId) {
      return res.json({ success:false, message:'You already proposed. Wait for your opponent to respond.' });
    }

    const pd = await db.collection('players').doc(playerId).get();
    const fromName = pd.exists ? (pd.data().clubName || pd.data().gameName || 'Your opponent') : 'Your opponent';

    const proposal = {
      fromPlayerId: playerId,
      fromName,
      slots: slotTs,
      round: newRound,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await fixRef.update({
      status:         'proposal_pending',
      proposalRound:  newRound,
      activeProposal: proposal,
      lastProposalAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const opponentId = isHome ? fix.playerBId : fix.playerAId;
    const notifType  = newRound === 1 ? 'TIME_PROPOSED' : 'TIME_COUNTER_PROPOSED';
    await _notifyProposal(notifType, opponentId, fixtureId, { fromName, slots: slotTs });

    // If this is round 2 and opponent still doesn't respond → admin notified by cron
    return res.json({ success:true, message: newRound === 1 ? 'Proposal sent to your opponent.' : 'Counter-proposal sent.' });
  } catch(e) {
    console.error('[CEE] proposeMatchTime:', e);
    return res.status(500).json({ success:false, message: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /respondToProposal — accept one slot OR reject all (triggers counter)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/respondToProposal', async (req, res) => {
  const { playerId, fixtureId, action, acceptedSlot } = req.body;
  // action: 'accept' | 'reject'
  if (!playerId || !fixtureId || !action)
    return res.status(400).json({ success:false, message:'Missing fields.' });

  try {
    const fixRef  = db.collection('fixtures').doc(fixtureId);
    const fixSnap = await fixRef.get();
    if (!fixSnap.exists) return res.json({ success:false, message:'Fixture not found.' });
    const fix = fixSnap.data();

    if (fix.status !== 'proposal_pending' || !fix.activeProposal)
      return res.json({ success:false, message:'No active proposal to respond to.' });

    // Only the non-proposing player can respond
    if (fix.activeProposal.fromPlayerId === playerId)
      return res.json({ success:false, message:'You are the proposer — wait for your opponent to respond.' });

    const isHome     = fix.playerAId === playerId;
    const proposerId = fix.activeProposal.fromPlayerId;

    if (action === 'accept') {
      if (!acceptedSlot) return res.json({ success:false, message:'Specify which slot you are accepting.' });
      const agreedTs   = admin.firestore.Timestamp.fromDate(new Date(acceptedSlot));
      const agreedDate = fromTS(agreedTs);
      // Check-in window: agreed time to agreed time + 20 mins
      const checkInOpen  = agreedTs;
      const checkInClose = admin.firestore.Timestamp.fromDate(agreedDate.plus({ minutes:20 }).toJSDate());

      await fixRef.update({
        status:          'time_agreed',
        agreedSlot:      agreedTs,
        checkInOpenAt:   checkInOpen,
        checkInCloseAt:  checkInClose,
        activeProposal:  admin.firestore.FieldValue.delete(),
        timeAgreedAt:    admin.firestore.FieldValue.serverTimestamp(),
        reminder1hSent:  false,
        reminder15mSent: false
      });

      // Notify both players
      await _notifyProposal('TIME_ACCEPTED', playerId,    fixtureId, { agreedSlot: agreedTs });
      await _notifyProposal('TIME_ACCEPTED', proposerId,  fixtureId, { agreedSlot: agreedTs });

      return res.json({ success:true, message:'Time confirmed! You\'ll receive reminders before the match.' });
    }

    if (action === 'reject') {
      // If already on round 2, escalate to admin instead of allowing a third round
      if ((fix.proposalRound || 0) >= 2) {
        await fixRef.update({ status:'admin_arbitration', activeProposal: admin.firestore.FieldValue.delete() });
        await _notifyProposal('ADMIN_ARBITRATION', playerId,   fixtureId, {});
        await _notifyProposal('ADMIN_ARBITRATION', proposerId, fixtureId, {});
        const adminChat = env.telegram && env.telegram.admin_chat_id;
        if (adminChat) await sendTelegram(adminChat,
          `⚖️ <b>Fixture needs arbitration</b>\nFixture ID: ${fixtureId}\nPlayers could not agree on a time after 2 rounds.`).catch(()=>{});
        await audit('ADMIN_ARBITRATION_TRIGGERED', fixtureId, 'fixture', 'Two proposal rounds exhausted');
        return res.json({ success:true, message:'Admin has been notified to assign a match time.' });
      }
      // Otherwise just mark it as awaiting a counter-proposal from this player
      await fixRef.update({ status:'awaiting_proposal' });
      return res.json({ success:true, message:'Slots rejected. You can now propose your own times.' });
    }

    return res.json({ success:false, message:'Unknown action.' });
  } catch(e) {
    console.error('[CEE] respondToProposal:', e);
    return res.status(500).json({ success:false, message: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /checkIn — player confirms they are present at the agreed time
// ─────────────────────────────────────────────────────────────────────────────
app.post('/checkIn', async (req, res) => {
  const { playerId, fixtureId } = req.body;
  if (!playerId || !fixtureId)
    return res.status(400).json({ success:false, message:'Missing fields.' });

  try {
    const fixRef  = db.collection('fixtures').doc(fixtureId);
    const fixSnap = await fixRef.get();
    if (!fixSnap.exists) return res.json({ success:false, message:'Fixture not found.' });
    const fix = fixSnap.data();

    if (fix.status !== 'checkin_open')
      return res.json({ success:false, message:'Check-in is not currently open for this fixture.' });

    const now       = nowWAT().toJSDate();
    const ciClose   = fix.checkInCloseAt ? fromTS(fix.checkInCloseAt).toJSDate() : null;
    if (ciClose && now > ciClose)
      return res.json({ success:false, message:'Check-in window has closed.' });

    const isHome       = fix.playerAId === playerId;
    const myField      = isHome ? 'playerACheckedIn' : 'playerBCheckedIn';
    const otherChecked = isHome ? fix.playerBCheckedIn : fix.playerACheckedIn;

    const update = { [myField]: admin.firestore.FieldValue.serverTimestamp() };

    if (otherChecked) {
      // Both checked in — match is now in progress
      const bothAt    = new Date();
      const winClose  = fix.windowCloseTime ? fix.windowCloseTime.toDate() : new Date(bothAt.getTime() + 8*3600000);
      const fiveHrs   = new Date(bothAt.getTime() + 5*3600*1000);
      const oneHrBuf  = new Date(winClose.getTime() - 3600*1000);
      update.status             = 'in_progress';
      update.bothReadyAt        = admin.firestore.Timestamp.fromDate(bothAt);
      update.submissionDeadline = admin.firestore.Timestamp.fromDate(fiveHrs < oneHrBuf ? fiveHrs : oneHrBuf);
      await fixRef.update(update);
      await _notifyBothReady(fix, fixtureId);
    } else {
      // First player checked in
      update.status = 'checkin_open'; // stays open, waiting for opponent
      await fixRef.update(update);
    }

    return res.json({ success:true, message: otherChecked ? 'Both checked in — match is live! Play and submit your score.' : 'Checked in! Waiting for your opponent.' });
  } catch(e) {
    console.error('[CEE] checkIn:', e);
    return res.status(500).json({ success:false, message: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /declareUnavailable — player flags they cannot play this window
// First use per season = no penalty. Second = warning. Third = forfeit.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/declareUnavailable', async (req, res) => {
  const { playerId, fixtureId, reason } = req.body;
  if (!playerId || !fixtureId || !reason)
    return res.status(400).json({ success:false, message:'A reason is required.' });

  const VALID_REASONS = ['exam', 'travel', 'power_outage', 'internet_outage', 'family_emergency', 'other'];
  if (!VALID_REASONS.includes(reason))
    return res.status(400).json({ success:false, message:'Invalid reason.' });

  try {
    const fixRef  = db.collection('fixtures').doc(fixtureId);
    const fixSnap = await fixRef.get();
    if (!fixSnap.exists) return res.json({ success:false, message:'Fixture not found.' });
    const fix = fixSnap.data();

    const closeable = ['window_open','awaiting_proposal','proposal_pending','time_agreed'];
    if (!closeable.includes(fix.status))
      return res.json({ success:false, message:'Cannot declare unavailability for this fixture status.' });

    // Check prior declarations this season
    const priorSnap = await db.collection('fixtures')
      .where('seasonId', '==', fix.seasonId)
      .where('unavailabilityDeclaredBy', '==', playerId)
      .get();
    const priorCount = priorSnap.size;

    let penalty = 'none';
    if (priorCount === 1) penalty = 'warning';
    if (priorCount >= 2)  penalty = 'forfeit';

    const isHome = fix.playerAId === playerId;
    const update = {
      unavailabilityDeclaredBy: playerId,
      unavailabilityReason:     reason,
      unavailabilityDeclaredAt: admin.firestore.FieldValue.serverTimestamp(),
      unavailabilityPenalty:    penalty,
      status:                   penalty === 'forfeit' ? 'approved' : 'admin_arbitration'
    };

    if (penalty === 'forfeit') {
      update.result        = isHome ? 'FORFEIT_A' : 'FORFEIT_B';
      update.playerAGoals  = isHome ? 0 : 3;
      update.playerBGoals  = isHome ? 3 : 0;
      update.done          = true;
      update.adminApproved = true;
      update.isForfeit     = true;
      update.autoApprovedAt = admin.firestore.FieldValue.serverTimestamp();
    }

    await fixRef.update(update);

    const adminChat  = env.telegram && env.telegram.admin_chat_id;
    const adminEmail = env.admin    && env.admin.email;
    const pd = await db.collection('players').doc(playerId).get();
    const pName = pd.exists ? (pd.data().clubName || pd.data().gameName || playerId) : playerId;

    const penaltyMessages = {
      none:    '✅ First declaration — no penalty. Admin will review.',
      warning: '⚠️ Second declaration — you have received a formal warning.',
      forfeit: '🚫 Third declaration — this fixture has been forfeited against you.'
    };

    const tgAdmin = `📋 <b>Unavailability Declared</b>\n\nPlayer: ${pName}\nFixture: ${fixtureId}\nReason: ${reason}\nPenalty: ${penalty.toUpperCase()}\nPrior declarations this season: ${priorCount}`;
    if (adminChat)  await sendTelegram(adminChat, tgAdmin).catch(()=>{});
    if (adminEmail) await sendEmail(adminEmail, 'CEE — Player Declared Unavailable', `<p>${tgAdmin.replace(/\n/g,'<br>')}</p>`).catch(()=>{});

    // Notify the opponent too
    const opponentId = isHome ? fix.playerBId : fix.playerAId;
    const oppPd = await db.collection('players').doc(opponentId).get();
    if (oppPd.exists) {
      const opp = oppPd.data();
      const oppMsg = `ℹ️ <b>Match Update</b>\n\nYour opponent (${pName}) has declared they cannot play this window.\nReason: ${reason}\n\nAdmin will review and assign a new time or apply the appropriate result.`;
      if (opp.telegramChatId) await sendTelegram(opp.telegramChatId, oppMsg).catch(()=>{});
      if (opp.email) await sendEmail(opp.email, 'CEE — Opponent Declared Unavailable', `<p>${oppMsg.replace(/\n/g,'<br>')}</p>`).catch(()=>{});
    }

    await audit('UNAVAILABILITY_DECLARED', fixtureId, 'fixture', `${pName}: ${reason} (penalty: ${penalty})`);
    return res.json({ success:true, penalty, message: penaltyMessages[penalty] });
  } catch(e) {
    console.error('[CEE] declareUnavailable:', e);
    return res.status(500).json({ success:false, message: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /submitScore — Gemini Vision AI, AC-1 club match, SHA-256 dedup
// NOI-2: timing check BEFORE _crossValidateScores
// ═══════════════════════════════════════════════════════════════════════════
app.post('/submitScore', async (req, res) => {
  const { fixtureId, playerId, isHome, imageData, mediaType, matchContext } = req.body;
  if (!fixtureId||!playerId||!imageData) return res.status(400).json({ success:false, message:'Missing fields' });
  try {
    const fixRef=db.collection('fixtures').doc(fixtureId);
    const fixSnap=await fixRef.get();
    if (!fixSnap.exists) return res.json({ success:false, message:'Fixture not found' });
    const fix=fixSnap.data();

    const nowJsDate=new Date();
    if (fix.windowCloseTime&&nowJsDate>fix.windowCloseTime.toDate())
      return res.json({ success:false, message:'Submission window has closed.' });
    if (fix.windowOpenTime&&nowJsDate<fix.windowOpenTime.toDate())
      return res.json({ success:false, message:'Match window has not opened yet.' });
    const alreadyKey=isHome?'playerASubmittedAt':'playerBSubmittedAt';
    if (fix[alreadyKey]) return res.json({ success:false, message:'You have already submitted.' });

    const imgBuf=Buffer.from(imageData,'base64');
    const imgHash=crypto.createHash('sha256').update(imgBuf).digest('hex');
    const myHash=isHome?fix.imageHashA:fix.imageHashB;
    const oppHash=isHome?fix.imageHashB:fix.imageHashA;
    if (myHash&&myHash===imgHash) return res.json({ success:false, message:'Duplicate image detected.' });
    if (oppHash&&oppHash===imgHash) {
      await fixRef.update({ screenshotFlaggedForReview:true, screenshotFlagReason:'Same image hash as opponent' });
      return res.json({ success:false, message:'Screenshot matches opponent submission — anti-cheat flag raised.' });
    }

    let ai={ isEfootballResultScreen:false,homeGoals:null,awayGoals:null,confidence:0,homeClubName:null,awayClubName:null,isPlausibleScore:false,isFullResultScreen:false,
             possessionHome:null,possessionAway:null,shotsHome:null,shotsAway:null,shotsOnTargetHome:null,shotsOnTargetAway:null,
             foulsHome:null,foulsAway:null,offsidesHome:null,offsidesAway:null,cornerKicksHome:null,cornerKicksAway:null,
             freeKicksHome:null,freeKicksAway:null,passesHome:null,passesAway:null,successfulPassesHome:null,successfulPassesAway:null,
             crossesHome:null,crossesAway:null,interceptionsHome:null,interceptionsAway:null,tacklesHome:null,tacklesAway:null,savesHome:null,savesAway:null };
    try {
      const _gRes=await _geminiPost({
          contents:[{parts:[
            {inline_data:{mime_type:mediaType||'image/jpeg',data:imageData}},
            {text:`You are the CEE Anti-Cheat Vision System — a fraud detection and stat extraction engine for the Campus eSports Elite eFootball tournament.\n\nYour job has TWO parts:\n\nPART 1 — FRAUD DETECTION (reason independently):\nExamine this screenshot and identify anything suspicious or inconsistent. Do NOT rely on rules given to you — reason from what you actually see in the image. Look for:\n- Signs of image editing: inconsistent fonts, pixel artifacts, blurry number regions, mismatched background textures, sharp edges around numbers suggesting overlay\n- Statistical impossibilities: e.g. more shots on target than total shots, possession values not summing to ~100, saves > shots on target, successful passes > total passes\n- Score/stat coherence: can the goals scored be explained by the shots on target and saves shown?\n- UI authenticity: does the screen look like a genuine eFootball post-match stats board? Check layout, colors, fonts, positioning of all elements\n- Scoreline plausibility: is the goal difference extreme? Are stats consistent with a high-scoring match?\n\nPART 2 — STAT EXTRACTION:\nExtract every number from the stats table precisely.\n\nRespond ONLY in JSON, no other text, no markdown:\n{\n  "isEfootballResultScreen": true/false,\n  "isFullResultScreen": true/false,\n  "homeGoals": <integer or null>,\n  "awayGoals": <integer or null>,\n  "homeClubName": "<string or null>",\n  "awayClubName": "<string or null>",\n  "isPlausibleScore": true/false,\n  "confidence": <float 0.0-1.0>,\n  "fraudSuspicion": <float 0.0-1.0>,\n  "fraudIndicators": [<array of strings — each a specific suspicious observation, empty array if none>],\n  "statisticalAnomalies": [<array of strings — each a stat that is mathematically inconsistent, empty if none>],\n  "uiAuthenticityScore": <float 0.0-1.0>,\n  "possessionHome": <integer 0-100 or null>,\n  "possessionAway": <integer 0-100 or null>,\n  "shotsHome": <integer or null>,\n  "shotsAway": <integer or null>,\n  "shotsOnTargetHome": <integer or null>,\n  "shotsOnTargetAway": <integer or null>,\n  "foulsHome": <integer or null>,\n  "foulsAway": <integer or null>,\n  "offsidesHome": <integer or null>,\n  "offsidesAway": <integer or null>,\n  "cornerKicksHome": <integer or null>,\n  "cornerKicksAway": <integer or null>,\n  "freeKicksHome": <integer or null>,\n  "freeKicksAway": <integer or null>,\n  "passesHome": <integer or null>,\n  "passesAway": <integer or null>,\n  "successfulPassesHome": <integer or null>,\n  "successfulPassesAway": <integer or null>,\n  "crossesHome": <integer or null>,\n  "crossesAway": <integer or null>,\n  "interceptionsHome": <integer or null>,\n  "interceptionsAway": <integer or null>,\n  "tacklesHome": <integer or null>,\n  "tacklesAway": <integer or null>,\n  "savesHome": <integer or null>,\n  "savesAway": <integer or null>\n}\nField rules:\n- fraudSuspicion: your overall confidence this screenshot has been tampered with. 0.0=definitely real, 1.0=definitely fraudulent. Be precise — do not default to 0.5.\n- fraudIndicators: list every specific visual or structural anomaly you detected. If none, empty array.\n- statisticalAnomalies: list any stat values that are mathematically impossible or highly improbable given the other stats.\n- uiAuthenticityScore: how closely the UI matches a genuine eFootball post-match stats board. 1.0=perfect match, 0.0=clearly not eFootball.\n- isPlausibleScore: false if goal difference >= 8 or either score > 15\n- confidence: your certainty that ALL stat values were read correctly. 1.0=certain, 0.0=unreadable.\n- possessionHome + possessionAway must sum to approximately 100\n- successfulPasses must be <= passes for each team\n- shotsOnTarget must be <= shots for each team\n- saves must be <= shotsOnTarget of the OPPOSING team\n- Set isEfootballResultScreen/isFullResultScreen to false and all stats to null if this is not a genuine eFootball stats board`}
          ]}],
          generationConfig:{maxOutputTokens:8000,temperature:0}
        });
      if (!_gRes.ok) throw new Error(_gRes.error || 'Gemini Vision call failed');
      const raw=(_gRes.data.candidates&&_gRes.data.candidates[0]&&_gRes.data.candidates[0].content&&_gRes.data.candidates[0].content.parts&&_gRes.data.candidates[0].content.parts[0]&&_gRes.data.candidates[0].content.parts[0].text)||'{}';
      ai=JSON.parse(raw.replace(/```json|```/g,'').trim());
    } catch(aiErr){ console.error('[CEE] Gemini Vision error:',aiErr.message); }

    if (!ai.isEfootballResultScreen||!ai.isFullResultScreen) {
      await audit('ANTICHEAT_INVALID_SCREENSHOT',fixtureId,'fixture',`Player ${playerId} submitted non-eFootball screenshot`);
      return res.json({ success:false, verificationState:'REJECTED', message:'❌ Not a valid eFootball result screen. Make sure you are submitting the full post-match stats screen, not a lineup, menu or other screen.' });
    }
    if (!ai.isPlausibleScore) {
      await fixRef.update({ collusionFlagGD:true });
      await audit('ANTICHEAT_FLAG',fixtureId,'fixture',`Implausible score: ${ai.homeGoals}-${ai.awayGoals}`);
    }

    // AC-1: club name fuzzy match
    try {
      const fixData=(await fixRef.get()).data();
      const pADoc=fixData.playerAId?await db.collection('players').doc(fixData.playerAId).get():null;
      const pBDoc=fixData.playerBId?await db.collection('players').doc(fixData.playerBId).get():null;
      const clubA=pADoc&&pADoc.exists?(pADoc.data().clubName||'').toLowerCase().trim():'';
      const clubB=pBDoc&&pBDoc.exists?(pBDoc.data().clubName||'').toLowerCase().trim():'';
      const ssHomeRaw=(ai.homeClubName||'').toLowerCase().trim();
      const ssAwayRaw=(ai.awayClubName||'').toLowerCase().trim();
      const onScreen=[ssHomeRaw,ssAwayRaw].filter(Boolean);
      const registered=[clubA,clubB].filter(Boolean);
      let bothMatch=false;
      if (onScreen.length>=2&&registered.length>=2) {
        const [ssH,ssA]=onScreen,[rA,rB]=registered;
        bothMatch=(_stringSimilarity(ssH,rA)>=CLUB_MATCH_THRESHOLD&&_stringSimilarity(ssA,rB)>=CLUB_MATCH_THRESHOLD)||
                  (_stringSimilarity(ssH,rB)>=CLUB_MATCH_THRESHOLD&&_stringSimilarity(ssA,rA)>=CLUB_MATCH_THRESHOLD);
      }
      if (onScreen.length>=2&&!bothMatch) {
        await fixRef.update({ clubNameMismatchFlag:true, clubNameMismatchDetail:`Screen: ${ssHomeRaw} vs ${ssAwayRaw} | Registered: ${clubA} vs ${clubB}` });
        await audit('ANTICHEAT_FLAG',fixtureId,'fixture',`Club name mismatch: ${ssHomeRaw}/${ssAwayRaw} vs ${clubA}/${clubB}`);
        return res.json({ success:false, message:'Club names on screenshot do not match this fixture. Make sure you are submitting the correct match result.' });
      }
    } catch(clubErr){ console.error('[CEE] Club name check:',clubErr.message); }

    const conf = ai.confidence || 0;
    const fraudSuspicion   = ai.fraudSuspicion   || 0;
    const uiAuthScore      = ai.uiAuthenticityScore != null ? ai.uiAuthenticityScore : 1.0;
    const fraudIndicators  = Array.isArray(ai.fraudIndicators)  ? ai.fraudIndicators  : [];
    const statAnomalies    = Array.isArray(ai.statisticalAnomalies) ? ai.statisticalAnomalies : [];

    let flagged = false, flagReason = '';
    // verificationState: 'APPROVED' | 'NEEDS_REVIEW' | 'REJECTED'
    let verificationState = 'APPROVED';

    // ── HARD REJECT: UI does not look like eFootball ─────────────────────────
    if (uiAuthScore < 0.50) {
      await fixRef.update({ screenshotFlaggedForReview: true, screenshotFlagReason: `UI authenticity too low (${Math.round(uiAuthScore*100)}%)`, status: 'admin_arbitration', fraudArbitrationAt: admin.firestore.FieldValue.serverTimestamp() });
      await audit('ANTICHEAT_UI_REJECTED', fixtureId, 'fixture', `UI authenticity ${Math.round(uiAuthScore*100)}% -- hard rejected`);
      _updatePlayerIntegrityScore(playerId, 'hard_flag').catch(()=>{});
      return res.json({ success: false, verificationState: 'REJECTED', message: `Screenshot rejected -- does not appear to be a genuine eFootball post-match stats screen (${Math.round(uiAuthScore*100)}% authenticity). Upload the correct screenshot.` });
    }

    // ── AI Fraud Detection ────────────────────────────────────────────────────
    if (fraudSuspicion >= 0.75) {
      const fraudDetail = [
        `AI fraud suspicion: ${Math.round(fraudSuspicion*100)}%`,
        `UI authenticity: ${Math.round(uiAuthScore*100)}%`,
        fraudIndicators.length ? 'Indicators: ' + fraudIndicators.join(' | ') : '',
        statAnomalies.length   ? 'Stat anomalies: ' + statAnomalies.join(' | ') : ''
      ].filter(Boolean).join(' -- ');
      await fixRef.update({ screenshotFlaggedForReview: true, screenshotFlagReason: fraudDetail, status: 'admin_arbitration', fraudArbitrationAt: admin.firestore.FieldValue.serverTimestamp() });
      await audit('ANTICHEAT_FRAUD_DETECTED', fixtureId, 'fixture', `High fraud suspicion from AI: ${fraudDetail}`);
      _updatePlayerIntegrityScore(playerId, 'hard_flag').catch(()=>{});
      const adminChat = env.telegram && env.telegram.admin_chat_id;
      if (adminChat) await sendTelegram(adminChat, `FRAUD ALERT\n\nFixture: ${fixtureId}\nPlayer: ${playerId}\nAI suspicion: ${Math.round(fraudSuspicion*100)}%\n${fraudIndicators.length ? fraudIndicators.slice(0,3).join(' | ') : ''}\n\nAction required -- Admin Arbitration`);
      return res.json({ success: false, verificationState: 'REJECTED', message: 'Screenshot failed our authenticity check. This submission has been flagged for admin review. Contact the league admin if you believe this is an error.' });
    } else if (fraudSuspicion >= 0.45) {
      flagged = true;
      verificationState = 'NEEDS_REVIEW';
      flagReason = `AI fraud suspicion ${Math.round(fraudSuspicion*100)}% -- ${fraudIndicators.slice(0,2).join('; ') || 'review recommended'}`;
      _updatePlayerIntegrityScore(playerId, 'soft_flag').catch(()=>{});
    }

    // ── Stat anomaly flag ─────────────────────────────────────────────────────
    if (statAnomalies.length > 0 && !flagged) {
      flagged = true;
      verificationState = 'NEEDS_REVIEW';
      flagReason = `Statistical anomalies detected: ${statAnomalies.slice(0,2).join('; ')}`;
    }

    // ── Standard confidence check ─────────────────────────────────────────────
    if (!flagged) {
      if (conf < 0.60) {
        const retryKey = isHome ? 'playerARetryCount' : 'playerBRetryCount';
        const retries  = fix[retryKey] || 0;
        if (retries >= 1) { flagged = true; verificationState = 'NEEDS_REVIEW'; flagReason = 'Low AI confidence after retry -- admin review required'; }
        else { await fixRef.update({ [retryKey]: retries+1 }); return res.json({ success:false, verificationState:'NEEDS_REVIEW', retry:true, confidence:conf, message:`Screenshot was unclear (${Math.round(conf*100)}% confidence). Try a brighter, sharper image of the full stats screen. You have 1 retry remaining.` }); }
      } else if (conf < 0.85) {
        flagged = true;
        verificationState = 'NEEDS_REVIEW';
        flagReason = `AI confidence ${Math.round(conf*100)}% -- below auto-accept threshold`;
      } else {
        _updatePlayerIntegrityScore(playerId, 'clean').catch(()=>{});
      }
    }
    const fname=`screenshots/${fixtureId}/${playerId}/${Date.now()}.jpg`;
    const bucket=storage.bucket(), file=bucket.file(fname);
    await file.save(imgBuf,{metadata:{contentType:mediaType||'image/jpeg'}});
    const [ssUrl]=await file.getSignedUrl({action:'read',expires:'03-01-2030'});

    const scoreStr=(ai.homeGoals!==null&&ai.awayGoals!==null)?`${ai.homeGoals}-${ai.awayGoals}`:'unknown';
    const sealed=crypto.createHash('sha256').update(scoreStr+fixtureId).digest('hex');
    const nowFV=admin.firestore.FieldValue.serverTimestamp();
    // Build full 26-field stats object from Gemini extraction
    const _aiStatsFull = {
      possessionHome:ai.possessionHome??null, possessionAway:ai.possessionAway??null,
      shotsHome:ai.shotsHome??null, shotsAway:ai.shotsAway??null,
      shotsOnTargetHome:ai.shotsOnTargetHome??null, shotsOnTargetAway:ai.shotsOnTargetAway??null,
      foulsHome:ai.foulsHome??null, foulsAway:ai.foulsAway??null,
      offsidesHome:ai.offsidesHome??null, offsidesAway:ai.offsidesAway??null,
      cornerKicksHome:ai.cornerKicksHome??null, cornerKicksAway:ai.cornerKicksAway??null,
      freeKicksHome:ai.freeKicksHome??null, freeKicksAway:ai.freeKicksAway??null,
      passesHome:ai.passesHome??null, passesAway:ai.passesAway??null,
      successfulPassesHome:ai.successfulPassesHome??null, successfulPassesAway:ai.successfulPassesAway??null,
      crossesHome:ai.crossesHome??null, crossesAway:ai.crossesAway??null,
      interceptionsHome:ai.interceptionsHome??null, interceptionsAway:ai.interceptionsAway??null,
      tacklesHome:ai.tacklesHome??null, tacklesAway:ai.tacklesAway??null,
      savesHome:ai.savesHome??null, savesAway:ai.savesAway??null
    };
    const update={};
    const _aiFraudData = { fraudSuspicion, uiAuthenticityScore: uiAuthScore, fraudIndicators, statisticalAnomalies: statAnomalies };
    if (isHome){ Object.assign(update,{playerAScoreSealed:sealed,playerAScreenshotUrl:ssUrl,playerASubmittedAt:nowFV,aiConfidenceA:conf,aiExtractedA:{home:ai.homeGoals,away:ai.awayGoals},aiStatsA:_aiStatsFull,aiFraudA:_aiFraudData,imageHashA:imgHash}); }
    else       { Object.assign(update,{playerBScoreSealed:sealed,playerBScreenshotUrl:ssUrl,playerBSubmittedAt:nowFV,aiConfidenceB:conf,aiExtractedB:{home:ai.homeGoals,away:ai.awayGoals},aiStatsB:_aiStatsFull,aiFraudB:_aiFraudData,imageHashB:imgHash}); }
    if (flagged){ update.screenshotFlaggedForReview=true; update.screenshotFlagReason=flagReason; }
    await fixRef.update(update);

    // ── CEE INTELLIGENCE: Write matchStats document (non-blocking background write) ──
    // Fires regardless of whether both players have submitted — we write on each submission
    // so data collection starts from Match Day 1.
    try {
      const seasonId = fix.seasonId || await getSeasonId();
      const matchStatDocId = `${fixtureId}_${playerId}`;
      const myGoals   = isHome ? (ai.homeGoals??0) : (ai.awayGoals??0);
      const oppGoals  = isHome ? (ai.awayGoals??0) : (ai.homeGoals??0);
      const result    = myGoals > oppGoals ? 'W' : myGoals < oppGoals ? 'L' : 'D';
      // Build per-player stats (from their own perspective: their team vs opponent)
      const myStats = {
        possession:       isHome ? (ai.possessionHome??null) : (ai.possessionAway??null),
        shots:            isHome ? (ai.shotsHome??null)       : (ai.shotsAway??null),
        shotsOnTarget:    isHome ? (ai.shotsOnTargetHome??null) : (ai.shotsOnTargetAway??null),
        fouls:            isHome ? (ai.foulsHome??null)        : (ai.foulsAway??null),
        offsides:         isHome ? (ai.offsidesHome??null)     : (ai.offsidesAway??null),
        cornerKicks:      isHome ? (ai.cornerKicksHome??null)  : (ai.cornerKicksAway??null),
        freeKicks:        isHome ? (ai.freeKicksHome??null)    : (ai.freeKicksAway??null),
        passes:           isHome ? (ai.passesHome??null)       : (ai.passesAway??null),
        successfulPasses: isHome ? (ai.successfulPassesHome??null) : (ai.successfulPassesAway??null),
        crosses:          isHome ? (ai.crossesHome??null)      : (ai.crossesAway??null),
        interceptions:    isHome ? (ai.interceptionsHome??null): (ai.interceptionsAway??null),
        tackles:          isHome ? (ai.tacklesHome??null)      : (ai.tacklesAway??null),
        saves:            isHome ? (ai.savesHome??null)        : (ai.savesAway??null)
      };
      const msWrite = {
        fixtureId, playerId, seasonId,
        opponentId: isHome ? fix.playerBId : fix.playerAId,
        matchDay:   fix.matchday || null,
        isHome:     !!isHome,
        result,
        goalsFor:    myGoals,
        goalsAgainst: oppGoals,
        verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
        stats:   myStats,
        context: matchContext || null
      };
      db.collection('matchStats').doc(matchStatDocId).set(msWrite, { merge:true })
        .catch(e => console.error('[CEE] matchStats write failed (non-blocking):', e.message));

      // ── C4: Rebuild playstyle fingerprint for this player (non-blocking) ──
      _buildPlaystyleFingerprint(playerId, seasonId).catch(
        e => console.error('[CEE] playstyleFingerprint error (non-blocking):', e.message)
      );

      // ── CEE INTELLIGENCE: Quick Match Analysis + Progressive Tips ────────────
      // Fires non-blocking after every verified submission.
      // Generates instant AI analysis of this match + comparison tips vs last match.
      _generateQuickAnalysis(playerId, fixtureId, fix, isHome, ai, myStats, matchContext).catch(
        e => console.error('[CEE] quickAnalysis error (non-blocking):', e.message)
      );

    } catch(msErr){ console.error('[CEE] matchStats prep error:', msErr.message); }

    const fresh=(await fixRef.get()).data();
    if (fresh.playerASubmittedAt&&fresh.playerBSubmittedAt) {
      // NOI-2: timing check FIRST so collusionFlagTime is visible inside _crossValidateScores
      const tsA=fresh.playerASubmittedAt.toDate().getTime();
      const tsB=fresh.playerBSubmittedAt.toDate().getTime();
      const diff=Math.abs(tsA-tsB)/1000;
      if (diff<30) {
        await fixRef.update({ collusionFlagTime:true, collusionFlagTimeDetail:`Both screenshots within ${diff.toFixed(1)}s` });
        await audit('ANTICHEAT_FLAG',fixtureId,'fixture',`Suspicious: both screenshots within ${diff.toFixed(1)}s`);
      } else if (diff>450) {
        await fixRef.update({ lateSubmissionFlag:true, lateSubmissionDetail:`${Math.round(diff/60)} min gap` });
        await audit('ANTICHEAT_FLAG',fixtureId,'fixture',`Suspicious: ${Math.round(diff/60)} min gap — exceeded 7.5 min window`);
      }

      // ── CEE INTELLIGENCE: Stat cross-validation ──────────────────────────────
      // Both players have now submitted. Compare the 14 stats extracted from each
      // screenshot. For a genuine match, both boards show the same numbers.
      // Any significant mismatch means the screenshots are from different matches.
      try {
        const statsA = fresh.aiStatsA || {};
        const statsB = fresh.aiStatsB || {};
        const statKeys = ['shotsHome','shotsAway','shotsOnTargetHome','shotsOnTargetAway',
                          'foulsHome','foulsAway','offsidesHome','offsidesAway',
                          'cornerKicksHome','cornerKicksAway','freeKicksHome','freeKicksAway',
                          'passesHome','passesAway','successfulPassesHome','successfulPassesAway',
                          'crossesHome','crossesAway','interceptionsHome','interceptionsAway',
                          'tacklesHome','tacklesAway','savesHome','savesAway'];
        const mismatches = [];
        let comparableStats = 0;
        for (const key of statKeys) {
          const vA = statsA[key], vB = statsB[key];
          if (vA !== null && vA !== undefined && vB !== null && vB !== undefined) {
            comparableStats++;
            if (vA !== vB) mismatches.push(`${key}: A=${vA} B=${vB}`);
          }
        }
        // Possession: allow ±3% tolerance due to display rounding
        const posHA = statsA.possessionHome, posHB = statsB.possessionHome;
        if (posHA !== null && posHA !== undefined && posHB !== null && posHB !== undefined) {
          comparableStats++;
          if (Math.abs(posHA - posHB) > 3) mismatches.push(`possessionHome: A=${posHA} B=${posHB}`);
        }
        // Significant mismatch threshold: if we have enough comparable stats AND
        // more than 20% of them differ, flag as stat mismatch.
        const mismatchRatio = comparableStats > 0 ? mismatches.length / comparableStats : 0;
        let _statMismatchDetected = false;
        if (comparableStats >= 6 && mismatchRatio > 0.2) {
          _statMismatchDetected = true;
          const mismatchDetail = `Stat mismatch (${mismatches.length}/${comparableStats} fields differ): ${mismatches.slice(0,5).join('; ')}`;
          // INTEL-06 FIX: escalate directly to admin_arbitration — do NOT enter pending_approval pipeline.
          // screenshotFlaggedForReview alone only delays auto-approval by 48hr; this makes it require
          // explicit admin resolution before the result is ever recorded.
          await fixRef.update({
            statMismatchFlag: true,
            statMismatchDetail: mismatchDetail,
            screenshotFlaggedForReview: true,
            screenshotFlagReason: mismatchDetail,
            status: 'admin_arbitration',
            statMismatchArbitrationAt: admin.firestore.FieldValue.serverTimestamp()
          });
          await audit('ANTICHEAT_STAT_MISMATCH', fixtureId, 'fixture', mismatchDetail);
          const adminChat = env.telegram && env.telegram.admin_chat_id;
          if (adminChat) {
            sendTelegram(adminChat, `🚨 <b>Stat Mismatch — Admin Action Required</b>\nFixture: ${fixtureId}\n${mismatchDetail}\nScreenshots appear to be from different matches.\n⚠️ Fixture moved to admin_arbitration — requires manual resolution.`).catch(()=>{});
          }
          console.warn(`[CEE] Stat mismatch on fixture ${fixtureId}: moved to admin_arbitration. ${mismatchDetail}`);
        }
      } catch(svErr){ console.error('[CEE] Stat cross-validation error:', svErr.message); }

      // INTEL-06 FIX: skip score cross-validation entirely when screenshots are confirmed
      // to be from different matches — there is nothing valid to cross-validate.
      if (!_statMismatchDetected) {
        await _crossValidateScores(fixtureId,fresh);
      }
    } else { await logNotif(fixtureId,playerId,'telegram','SUBMISSION_RECEIVED','sent'); }

    const _detectedA = ai.homeGoals !== null && ai.homeGoals !== undefined ? ai.homeGoals : '?';
    const _detectedB = ai.awayGoals !== null && ai.awayGoals !== undefined ? ai.awayGoals : '?';
    return res.json({ success:true, verificationState, confidence:conf, detectedScore:`${_detectedA} - ${_detectedB}`, homeGoals: ai.homeGoals, awayGoals: ai.awayGoals, message: verificationState === 'NEEDS_REVIEW' ? 'Screenshot received but flagged for admin review. Result will be confirmed once reviewed.' : 'Screenshot verified and sealed. Awaiting opponent submission.' });
  } catch(e){ console.error('[CEE] submitScore:',e); return res.status(500).json({ success:false, message:'Server error: '+e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// C4: PLAYSTYLE FINGERPRINT ENGINE
// Aggregates ALL-TIME formation, attack direction, and pressing tendencies
// across every verified matchStats doc for a player.
// Stored as playerProfile/{playerId} — injected into scout reports as
// confirmed tendencies rather than per-match observations.
// Updates non-blocking after every new match submission.
// ═══════════════════════════════════════════════════════════════════════════
async function _buildPlaystyleFingerprint(playerId, seasonId) {
  try {
    // Fetch all matchStats for this player this season
    const snap = await db.collection('matchStats')
      .where('playerId', '==', playerId)
      .where('seasonId', '==', seasonId)
      .get();

    const matches = [];
    snap.forEach(d => matches.push(d.data()));

    // ── Also pull from identity-linked previous player IDs ───────────────────
    // This makes the fingerprint truly all-time, not just current season.
    // A returning player with 0 current-season matches still gets a fingerprint
    // from their previous season history — vital for Season 2 early matchdays.
    try {
      const pdSnap = await db.collection('players').doc(playerId).get();
      if (pdSnap.exists) {
        const linkedIds = pdSnap.data().linkedPreviousPlayerIds || [];
        if (linkedIds.length > 0) {
          const batchSize = Math.min(linkedIds.length, 10);
          const histSnap = await db.collection('matchStats')
            .where('playerId', 'in', linkedIds.slice(0, batchSize))
            .get();
          histSnap.forEach(d => matches.push({ ...d.data(), _historical: true }));
        }
      }
    } catch(e) { /* non-fatal — fingerprint still works from current season only */ }

    // Nothing to fingerprint even after cross-season pull — bail
    if (!matches.length) return;

    const n = matches.length;

    // ── Formation frequency ──────────────────────────────────────────────────
    const formationCount = {};
    matches.forEach(m => {
      if (m.context && m.context.formation) {
        formationCount[m.context.formation] = (formationCount[m.context.formation] || 0) + 1;
      }
    });
    const formationEntries = Object.entries(formationCount)
      .sort((a, b) => b[1] - a[1])
      .map(([f, cnt]) => ({ formation: f, count: cnt, pct: Math.round((cnt / n) * 100) }));

    // ── Attack direction frequency ────────────────────────────────────────────
    const attackCount = {};
    matches.forEach(m => {
      if (m.context && m.context.attackDirection) {
        attackCount[m.context.attackDirection] = (attackCount[m.context.attackDirection] || 0) + 1;
      }
    });
    const attackEntries = Object.entries(attackCount)
      .sort((a, b) => b[1] - a[1])
      .map(([dir, cnt]) => ({ direction: dir, count: cnt, pct: Math.round((cnt / n) * 100) }));

    // ── Behavioural tendencies ────────────────────────────────────────────────
    const ctxMatches = matches.filter(m => m.context);
    const ctxN = ctxMatches.length || 1;
    const pressing   = ctxMatches.filter(m => m.context.opponentPressing   === true).length;
    const defensive  = ctxMatches.filter(m => m.context.opponentDefensive  === true).length;
    const scoredFirst= ctxMatches.filter(m => m.context.scoredFirst        === true).length;
    const setpiece   = ctxMatches.filter(m => m.context.setpieceGoal       === true).length;
    const momentum   = ctxMatches.filter(m => m.context.momentumShift      === true).length;
    const subs       = ctxMatches.filter(m => m.context.madeSubstitutions  === true).length;

    // ── Build readable fingerprint text for scout prompt injection ────────────
    let fingerprintText = `CONFIRMED PLAYSTYLE PROFILE (based on ${n} verified match${n !== 1 ? 'es' : ''} this season):
`;

    if (formationEntries.length > 0) {
      fingerprintText += `Formation: ${formationEntries.map(e => `${e.formation} (${e.pct}%)`).join(', ')}
`;
    } else {
      fingerprintText += `Formation: No formation data (questionnaire not completed)
`;
    }

    if (attackEntries.length > 0) {
      fingerprintText += `Attack direction: ${attackEntries.map(e => `${e.direction === 'wings' ? 'Out Wide' : 'Through Middle'} (${e.pct}%)`).join(', ')}
`;
    } else {
      fingerprintText += `Attack direction: No data
`;
    }

    if (ctxMatches.length >= 2) {
      fingerprintText += `Scores first: ${scoredFirst}/${ctxN} matches (${Math.round((scoredFirst/ctxN)*100)}%) -- ${scoredFirst >= ctxN*0.6 ? 'FRONT-LOADED STYLE' : scoredFirst <= ctxN*0.2 ? 'PLAYS FROM BEHIND' : 'balanced'}
`;
      fingerprintText += `Faces high press: ${pressing}/${ctxN} matches (${Math.round((pressing/ctxN)*100)}%)
`;
      fingerprintText += `Opponent sat back: ${defensive}/${ctxN} matches (${Math.round((defensive/ctxN)*100)}%)
`;
      fingerprintText += `Set piece goals: ${setpiece}/${ctxN} matches (${Math.round((setpiece/ctxN)*100)}%) -- ${setpiece >= ctxN*0.3 ? 'SET PIECE THREAT' : 'not a set piece scorer'}
`;
      fingerprintText += `Momentum shifts: ${momentum}/${ctxN} matches (${Math.round((momentum/ctxN)*100)}%) -- ${momentum >= ctxN*0.4 ? 'SECOND-HALF VULNERABILITY' : 'momentum-stable'}
`;
      fingerprintText += `Uses subs: ${subs}/${ctxN} matches (${Math.round((subs/ctxN)*100)}%) -- ${subs >= ctxN*0.6 ? 'ROTATION-DEPENDENT' : 'consistent lineup'}
`;
    } else {
      fingerprintText += `Behavioural data: Insufficient questionnaire submissions (${ctxMatches.length} completed)
`;
    }

    // ── Write to playerProfile collection ────────────────────────────────────
    await db.collection('playerProfile').doc(playerId).set({
      playerId,
      seasonId,
      matchCount: n,
      formationEntries,
      attackEntries,
      tendencies: { pressing, defensive, scoredFirst, setpiece, momentum, subs, ctxN },
      fingerprintText,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log(`[CEE] Playstyle fingerprint updated: ${playerId} (${n} matches)`);
  } catch(e) { console.error('[CEE] _buildPlaystyleFingerprint error:', e.message); }
}

// ═══════════════════════════════════════════════════════════════════════════
// CEE INTELLIGENCE: _generateQuickAnalysis
// Fires non-blocking after every verified screenshot submission.
// PART A: Instant match analysis from extracted stats -- always generated.
// PART B: Progressive tips comparing this match to player's previous match.
// Both stored on fixture (quickAnalysisA/B) and served via GET /getQuickAnalysis.
// Also writes to playerStatHistory for long-term per-player memory.
// ═══════════════════════════════════════════════════════════════════════════
async function _generateQuickAnalysis(playerId, fixtureId, fix, isHome, ai, myStats, matchContext) {
  try {
    const seasonId   = fix.seasonId || await getSeasonId();
    const myGoals    = isHome ? (ai.homeGoals||0) : (ai.awayGoals||0);
    const oppGoals   = isHome ? (ai.awayGoals||0) : (ai.homeGoals||0);
    const result     = myGoals > oppGoals ? 'W' : myGoals < oppGoals ? 'L' : 'D';
    const resultStr  = result === 'W' ? `Won ${myGoals}-${oppGoals}` : result === 'L' ? `Lost ${myGoals}-${oppGoals}` : `Drew ${myGoals}-${oppGoals}`;

    const pdSnap     = await db.collection('players').doc(playerId).get();
    const playerName = pdSnap.exists ? (pdSnap.data().clubName || pdSnap.data().gameName || 'Player') : 'Player';

    const passAcc  = myStats.passes && myStats.passes > 0 && myStats.successfulPasses != null
      ? Math.round((myStats.successfulPasses / myStats.passes) * 100) + '%' : 'N/A';
    const shotQual = myStats.shots && myStats.shots > 0 && myStats.shotsOnTarget != null
      ? Math.round((myStats.shotsOnTarget / myStats.shots) * 100) + '%' : 'N/A';

    const statsBlock = `Match result: ${resultStr}
Possession: ${myStats.possession != null ? myStats.possession+'%' : 'N/A'} | Shots: ${myStats.shots??'N/A'} (${myStats.shotsOnTarget??'?'} on target) | Shot quality: ${shotQual}
Passes: ${myStats.passes??'N/A'} (${myStats.successfulPasses??'?'} successful) | Pass accuracy: ${passAcc}
Tackles: ${myStats.tackles??'N/A'} | Interceptions: ${myStats.interceptions??'N/A'} | Saves: ${myStats.saves??'N/A'}
Crosses: ${myStats.crosses??'N/A'} | Corners: ${myStats.cornerKicks??'N/A'} | Fouls: ${myStats.fouls??'N/A'} | Offsides: ${myStats.offsides??'N/A'}
${matchContext ? `Formation: ${matchContext.formation||'unknown'} | Attack direction: ${matchContext.attackDirection||'unknown'}${matchContext.scoredFirst?' | Scored first':''}${matchContext.setpieceGoal?' | Set piece goal':''}${matchContext.momentumShift?' | Felt momentum shift':''}` : 'Post-match questionnaire: not completed this match'}`;

    // ── Fetch previous match for progressive tips (cross-season aware) ────
    let lastMatchBlock = '';
    let hasLastMatch   = false;
    let prevMatchDay   = '?';
    try {
      const prevSnap = await db.collection('matchStats')
        .where('playerId', '==', playerId)
        .where('seasonId', '==', seasonId)
        .orderBy('verifiedAt', 'desc')
        .limit(2)
        .get();
      // Cross-season fallback: if first match of the season, pull last match from prev season
      let prevDoc = null;
      if (prevSnap.size >= 2) {
        prevDoc = prevSnap.docs[1].data();
      } else {
        // Try previous season via linkedPreviousPlayerIds
        const pdFull = pdSnap.exists ? pdSnap.data() : {};
        const linkedIds = pdFull.linkedPreviousPlayerIds || [];
        if (linkedIds.length > 0) {
          const xSnap = await db.collection('matchStats')
            .where('playerId', 'in', linkedIds.slice(0,10))
            .orderBy('verifiedAt', 'desc')
            .limit(1)
            .get();
          if (!xSnap.empty) prevDoc = { ...xSnap.docs[0].data(), _prevSeason: true };
        }
      }
      if (prevDoc) {
        const prev  = prevDoc;
        const ps    = prev.stats || {};
        const pAcc  = ps.passes && ps.passes > 0 && ps.successfulPasses != null ? Math.round((ps.successfulPasses/ps.passes)*100)+'%' : 'N/A';
        const pSQ   = ps.shots  && ps.shots  > 0 && ps.shotsOnTarget    != null ? Math.round((ps.shotsOnTarget/ps.shots)*100)+'%'    : 'N/A';
        const pRes  = prev.result==='W' ? `Won ${prev.goalsFor}-${prev.goalsAgainst}` : prev.result==='L' ? `Lost ${prev.goalsFor}-${prev.goalsAgainst}` : `Drew ${prev.goalsFor}-${prev.goalsAgainst}`;
        prevMatchDay = prev.matchDay || '?';
        lastMatchBlock = `
PREVIOUS MATCH (Match Day ${prev.matchDay||'?'}):
Result: ${pRes}
Possession: ${ps.possession!=null?ps.possession+'%':'N/A'} | Shots: ${ps.shots??'N/A'} (${ps.shotsOnTarget??'?'} on target) | Shot quality: ${pSQ}
Passes: ${ps.passes??'N/A'} (${ps.successfulPasses??'?'} successful) | Pass accuracy: ${pAcc}
Tackles: ${ps.tackles??'N/A'} | Interceptions: ${ps.interceptions??'N/A'} | Saves: ${ps.saves??'N/A'}
${prev.context ? `Formation: ${prev.context.formation||'unknown'} | Attack: ${prev.context.attackDirection||'unknown'}` : ''}`;
        prevMatchDay = prev.matchDay || (prev._prevSeason ? '[prev season]' : '?');
        hasLastMatch = true;
      }
    } catch(e2) { console.error('[CEE] quickAnalysis prev fetch:', e2.message); }

    // ── Build prompt ──────────────────────────────────────────────────────────
    const isCrossSeasonCompare = hasLastMatch && lastMatchBlock.includes('[prev season]');
    const prompt = hasLastMatch ? `You are a personal eFootball coach reviewing a player's stats across recent matches. Here are their stats from their last match and their current match. Compare them directly. Tell the player: 1) What improved, 2) What got worse, 3) One specific thing to work on before their next match. Reference actual numbers. Be encouraging but honest. Maximum 12 lines.${isCrossSeasonCompare ? ' Note: the previous match shown is from a previous season — acknowledge this briefly and focus on what has carried over.' : ''}

PLAYER: ${playerName}

LAST MATCH (Match Day ${prevMatchDay}):
${lastMatchBlock.trim()}

CURRENT MATCH (Match Day ${fix.matchday||'?'}):
${statsBlock}
${matchContext ? `Post-match context: formation=${matchContext.formation||'?'}, attack=${matchContext.attackDirection||'?'}, scored first=${matchContext.scoredFirst===true?'yes':matchContext.scoredFirst===false?'no':'?'}, opp pressed=${matchContext.opponentPressing===true?'yes':matchContext.opponentPressing===false?'no':'?'}, opp sat back=${matchContext.opponentDefensive===true?'yes':matchContext.opponentDefensive===false?'no':'?'}, set piece goal=${matchContext.setpieceGoal===true?'yes':matchContext.setpieceGoal===false?'no':'?'}, momentum shift=${matchContext.momentumShift===true?'yes':matchContext.momentumShift===false?'no':'?'}, substitutions=${matchContext.madeSubstitutions===true?'yes':matchContext.madeSubstitutions===false?'no':'?'}, self-mistake=${matchContext.selfMistakeGoal===true?'yes':matchContext.selfMistakeGoal===false?'no':'?'}` : 'Post-match questionnaire: not completed'}`

    : `You are a personal eFootball coach giving instant post-match feedback to ${playerName}.

Here are their stats from their current match. Analyse what the numbers reveal about how the game was played — what worked, what didn't, and why the result happened. Reference actual numbers. Be encouraging but honest. Maximum 8 lines.

Add one final line: "Answer the post-match questionnaire each match to unlock personalised improvement tips comparing your matches."

CURRENT MATCH (Match Day ${fix.matchday||'?'}):
${statsBlock}`;

    // ── Gemini call ───────────────────────────────────────────────────────────
    const gaRes = await _geminiPost({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 1200, temperature: 0.2 }
    });
    if (!gaRes.ok) { console.warn('[CEE] quickAnalysis Gemini failed:', gaRes.error); return; }

    const text = (gaRes.data.candidates&&gaRes.data.candidates[0]&&gaRes.data.candidates[0].content&&gaRes.data.candidates[0].content.parts&&gaRes.data.candidates[0].content.parts[0]&&gaRes.data.candidates[0].content.parts[0].text) || '';
    if (!text.trim()) return;

    // ── Store on fixture ──────────────────────────────────────────────────────
    const field = isHome ? 'quickAnalysisA' : 'quickAnalysisB';
    await db.collection('fixtures').doc(fixtureId).update({
      [field]: text.trim(),
      [`${field}GeneratedAt`]: admin.firestore.FieldValue.serverTimestamp()
    });

    // ── Write to playerStatHistory for long-term memory ───────────────────────
    db.collection('playerStatHistory').doc(`${playerId}_${fixtureId}`).set({
      playerId, seasonId, fixtureId,
      matchDay:     fix.matchday    || null,
      result, goalsFor: myGoals, goalsAgainst: oppGoals,
      stats:        myStats,
      context:      matchContext    || null,
      quickAnalysis: text.trim(),
      recordedAt:   admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true }).catch(e => console.error('[CEE] playerStatHistory write failed:', e.message));

    console.log(`[CEE] Quick analysis generated for ${playerName} fixture ${fixtureId}`);
  } catch(e) { console.error('[CEE] _generateQuickAnalysis error:', e.message); }
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /getQuickAnalysis?fixtureId=X&playerId=Y
// Returns the quick match analysis + progressive tips for a player.
// Called by frontend after submission — poll until success:true.
// ═══════════════════════════════════════════════════════════════════════════
app.get('/getQuickAnalysis', async (req, res) => {
  const { fixtureId, playerId } = req.query;
  if (!fixtureId || !playerId) return res.status(400).json({ success: false, message: 'Missing fields.' });
  try {
    const fixSnap = await db.collection('fixtures').doc(fixtureId).get();
    if (!fixSnap.exists) return res.json({ success: false, message: 'Fixture not found.' });
    const fix    = fixSnap.data();
    const isHome = fix.playerAId === playerId;
    const field  = isHome ? 'quickAnalysisA' : 'quickAnalysisB';
    const text   = fix[field] || null;
    const genAt  = fix[`${field}GeneratedAt`] ? fix[`${field}GeneratedAt`].toDate().toISOString() : null;
    if (!text) return res.json({ success: false, reason: 'not_ready', message: 'Analysis is being generated. Check back in a moment.' });
    return res.json({ success: true, analysis: text, generatedAt: genAt });
  } catch(e) { return res.status(500).json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /issuePinForPlayer — admin issues PIN on registration approval
// ═══════════════════════════════════════════════════════════════════════════
app.post('/issuePinForPlayer', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { regId, seasonId } = req.body;
  if (!regId||!seasonId) return res.status(400).json({ success:false, message:'Missing fields' });
  try {
    const regDoc=await db.collection('registrations').doc(regId).get();
    if (!regDoc.exists) return res.json({ success:false, message:'Registration not found' });
    const reg=regDoc.data();
    if (!reg.email) return res.json({ success:false, message:'No email in registration' });
    const pin=String(Math.floor(1000+Math.random()*9000));
    const pinHash=await bcrypt.hash(pin,12);
    const ps=await db.collection('players').where('seasonId','==',seasonId).where('email','==',reg.email).limit(1).get();
    if (!ps.empty) {
      await db.collection('playerSecrets').doc(ps.docs[0].id).set(
        {pinHash,pinFailAttempts:0,pinLockoutUntil:null,pinLockoutCount:0},{merge:true});
      await ps.docs[0].ref.update({pinIssuedAt:admin.firestore.FieldValue.serverTimestamp()});
    }
    await regDoc.ref.update({pinIssuedAt:admin.firestore.FieldValue.serverTimestamp()});
    const emailRes=await sendEmail(reg.email,'CEE — Your Player PIN (Keep Safe!)',
      `<p>Welcome to <strong>Campus eSports Elite</strong>!</p>
       <p>Your registration is approved. Your unique Player PIN is:</p>
       <div class="hl" style="font-size:36px;font-weight:700;letter-spacing:.5em;text-align:center">${pin}</div>
       <p><strong>This is your only copy.</strong> Memorise it — it will not be shown again.</p>
       <p>Use this PIN in the CEE Player Hub to mark Ready, submit scores, and view your fixtures.</p>`);
    if (!emailRes.success) return res.json({ success:false, message:'PIN set but email failed: '+emailRes.error });
    await logNotif(null,reg.email,'email','PIN_ISSUED','sent');
    await audit('PIN_ISSUED',regId,'player','PIN issued to '+reg.email);
    return res.json({ success:true, message:'PIN issued and emailed.' });
  } catch(e){ console.error('[CEE] issuePinForPlayer:',e); return res.status(500).json({ success:false, message:'Server error' }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /adminResetPin — NEW-02: validates 4-digit format
// ═══════════════════════════════════════════════════════════════════════════
app.post('/adminResetPin', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { playerId, newPin } = req.body;
  if (!playerId) return res.status(400).json({ success:false, message:'Missing playerId' });
  if (newPin!==undefined&&!/^\d{4}$/.test(String(newPin)))
    return res.status(400).json({ success:false, message:'newPin must be a 4-digit number.' });
  try {
    const pd=await db.collection('players').doc(playerId).get();
    if (!pd.exists) return res.status(404).json({ success:false });
    const player=pd.data();
    const pin=newPin||String(Math.floor(1000+Math.random()*9000));
    const pinHash=await bcrypt.hash(pin,12);
    await db.collection('playerSecrets').doc(playerId).set(
      {pinHash,pinFailAttempts:0,pinLockoutUntil:null,pinLockoutCount:0},{merge:true});
    if (player.email) {
      await sendEmail(player.email,'CEE — Your PIN Has Been Reset',
        `<p>Your CEE login PIN has been reset by the administrator.</p>
         <div class="hl" style="font-size:24px;font-weight:700;letter-spacing:.2em;text-align:center">${pin}</div>
         <p>⚠️ Keep this PIN private. Use it to access the CEE Player Hub.</p>`);
    }
    await logNotif(null,playerId,'email','PIN_ISSUED','sent');
    await audit('PIN_RESET',playerId,'player','Admin reset PIN');
    return res.json({ success:true });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /blockPlayer | /unblockPlayer — admin can revoke/restore hub access
// ═══════════════════════════════════════════════════════════════════════════
app.post('/blockPlayer', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { playerId, reason } = req.body;
  if (!playerId) return res.status(400).json({ success:false, message:'Missing playerId' });
  try {
    const pd = await db.collection('players').doc(playerId).get();
    if (!pd.exists) return res.status(404).json({ success:false, message:'Player not found' });
    const player = pd.data();
    await db.collection('players').doc(playerId).update({
      hubBlocked: true,
      hubBlockedReason: reason || 'Blocked by admin',
      hubBlockedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    // Invalidate their PIN so they cannot log in even with old PIN
    await db.collection('playerSecrets').doc(playerId).set(
      { pinHash: null, pinFailAttempts: 0, pinLockoutUntil: null }, { merge: true }
    );
    if (player.email) {
      await sendEmail(player.email, 'CEE — Account Suspended',
        `<p>Your CEE Player Hub access has been suspended by the administrator.</p>
         ${reason ? `<div class="hl">Reason: ${reason}</div>` : ''}
         <p>Contact the league admin if you believe this is an error.</p>`
      );
    }
    await audit('PLAYER_BLOCKED', playerId, 'player', reason || 'No reason given');
    return res.json({ success: true });
  } catch(e) { return res.status(500).json({ success: false, message: e.message }); }
});

app.post('/unblockPlayer', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { playerId } = req.body;
  if (!playerId) return res.status(400).json({ success:false, message:'Missing playerId' });
  try {
    const pd = await db.collection('players').doc(playerId).get();
    if (!pd.exists) return res.status(404).json({ success:false, message:'Player not found' });
    const player = pd.data();
    // Issue a fresh PIN automatically on unblock
    const newPin = String(Math.floor(1000 + Math.random() * 9000));
    const pinHash = await bcrypt.hash(newPin, 12);
    await db.collection('players').doc(playerId).update({
      hubBlocked: false, hubBlockedReason: null, hubBlockedAt: null
    });
    await db.collection('playerSecrets').doc(playerId).set(
      { pinHash, pinFailAttempts: 0, pinLockoutUntil: null, pinLockoutCount: 0 }, { merge: true }
    );
    if (player.email) {
      await sendEmail(player.email, 'CEE — Account Reinstated',
        `<p>Your CEE Player Hub access has been reinstated.</p>
         <p>A new PIN has been issued:</p>
         <div class="hl" style="font-size:28px;font-weight:700;letter-spacing:.3em;text-align:center">${newPin}</div>
         <p>⚠️ Keep this PIN private.</p>`
      );
    }
    await audit('PLAYER_UNBLOCKED', playerId, 'player', 'Account reinstated, new PIN issued');
    return res.json({ success: true, message: 'Player unblocked and new PIN emailed.' });
  } catch(e) { return res.status(500).json({ success: false, message: e.message }); }
});

// ─────────────────────────────────────────────────────────────────────────────

// ── Admin: Generate VAPID keys (one-shot — copy output to Railway env vars) ──
app.get('/adminGenerateVapidKeys', (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  try {
    const { generateKeyPairSync } = require('crypto');
    // Generate EC P-256 key pair — use JWK export to get exact private scalar (d)
    // and build uncompressed public key from x,y coordinates.
    // DO NOT use slice(-32) on PKCS8 DER — it extracts wrong bytes (end of public key).
    const keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = keyPair.privateKey.export({ format: 'jwk' });
    // Private scalar: jwk.d is already base64url-encoded 32-byte scalar
    const privKeyBase64url = jwk.d;
    // Public key: uncompressed point 0x04 || x || y = 65 bytes
    const pubKey65 = Buffer.concat([
      Buffer.from([0x04]),
      Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url')
    ]);
    const pubKeyBase64url = pubKey65.toString('base64url');
    res.json({
      success: true,
      message: 'Copy these two values to Railway → Variables. Then redeploy.',
      VAPID_PUBLIC_KEY:  pubKeyBase64url,
      VAPID_PRIVATE_KEY: privKeyBase64url,
      instructions: [
        '1. Go to Railway → your backend service → Variables',
        '2. Set VAPID_PUBLIC_KEY = ' + pubKeyBase64url,
        '3. Set VAPID_PRIVATE_KEY = ' + privKeyBase64url,
        '4. Click Deploy',
        '5. Come back and click Enable Push — it will work'
      ]
    });
  } catch(e) {
    res.json({ success: false, message: e.message });
  }
});
// GET /vapidPublicKey — frontend calls this once on load to get the VAPID key
// ─────────────────────────────────────────────────────────────────────────────
app.get('/vapidPublicKey', (req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.json({ ok: false, message: 'Web push not configured on this server.' });
  // Strip whitespace/quotes in case key was pasted with extra chars in Railway
  const cleanKey = VAPID_PUBLIC_KEY.replace(/[\s"']/g, '').trim();
  res.json({ ok: true, publicKey: cleanKey });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /savePushSubscription — called after browser subscribe(), saves to Firestore
// Body: { playerId, subscription: { endpoint, keys: { p256dh, auth } } }
// ─────────────────────────────────────────────────────────────────────────────
app.post('/savePushSubscription', async (req, res) => {
  const { playerId, subscription } = req.body;
  if (!playerId || !subscription || !subscription.endpoint || !subscription.keys)
    return res.status(400).json({ ok: false, message: 'playerId and subscription required.' });
  try {
    await db.collection('players').doc(String(playerId)).update({
      pushSubscription:   JSON.stringify(subscription),
      notificationsPush:  true,
      pushSubscribedAt:   admin.firestore.FieldValue.serverTimestamp()
    });
    console.log(`[CEE] Push subscription saved for ${playerId}`);
    return res.json({ ok: true });
  } catch(e) {
    console.error('[CEE] savePushSubscription error:', e.message);
    return res.status(500).json({ ok: false, message: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /deletePushSubscription — called when player turns off push in hub
// Body: { playerId }
// ─────────────────────────────────────────────────────────────────────────────
app.post('/deletePushSubscription', async (req, res) => {
  const { playerId } = req.body;
  if (!playerId) return res.status(400).json({ ok: false, message: 'playerId required.' });
  try {
    await db.collection('players').doc(String(playerId)).update({
      pushSubscription:  admin.firestore.FieldValue.delete(),
      notificationsPush: false
    });
    return res.json({ ok: true });
  } catch(e) {
    return res.status(500).json({ ok: false, message: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /testPushNotification — sends a live test push to a specific player
// Body: { playerId } — admin only
// ─────────────────────────────────────────────────────────────────────────────
app.post('/testPushNotification', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  const { playerId } = req.body;
  if (!playerId) return res.status(400).json({ ok: false, message: 'playerId required.' });
  try {
    const snap = await db.collection('players').doc(String(playerId)).get();
    if (!snap.exists) return res.json({ ok: false, message: 'Player not found.' });
    const p = snap.data();
    if (!p.pushSubscription) return res.json({ ok: false, message: 'Player has no push subscription saved.' });
    let sub;
    try { sub = typeof p.pushSubscription === 'string' ? JSON.parse(p.pushSubscription) : p.pushSubscription; }
    catch(e) { return res.json({ ok: false, message: 'Subscription data corrupt.' }); }
    const r = await _sendWebPush(sub, {
      title: '🧪 CEE Push Test',
      body:  'Web push is working! You\'ll get match notifications here.',
      eventType: 'TEST',
      data: { url: `${process.env.SITE_URL || 'https://cee-esports.web.app'}#hub` }
    });
    if (!r.ok && r.expired) {
      await db.collection('players').doc(String(playerId)).update({ pushSubscription: admin.firestore.FieldValue.delete() }).catch(()=>{});
      return res.json({ ok: false, message: 'Subscription expired — player needs to re-enable push notifications.' });
    }
    return res.json(r);
  } catch(e) {
    return res.status(500).json({ ok: false, message: e.message });
  }
});

app.post('/sendNotification', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { playerIds, recipientId, message, channel, eventType } = req.body;
  const target = playerIds || recipientId;
  const subj   = `CEE — ${(eventType||'Notification').replace(/_/g,' ')}`;
  const html   = `<p>${message.replace(/\n/g,'<br>')}</p>`;

  try {
    let recipients = []; // array of player doc IDs

    // No target = admin-only message (send to admin Telegram/email only)
    if (!target) {
      const adminChat  = env.telegram && env.telegram.admin_chat_id;
      const adminEmail = env.admin    && env.admin.email;
      if (adminChat  && (!channel || channel === 'telegram' || channel === 'both'))
        await sendTelegram(adminChat, message).catch(()=>{});
      if (adminEmail && (!channel || channel === 'email'    || channel === 'both'))
        await sendEmail(adminEmail, subj, html).catch(()=>{});
      return res.json({ success: true });
    }

    if (target === 'all') {
      const sid = await getSeasonId();
      if (sid) {
        const snap = await db.collection('players').where('seasonId','==',sid).get();
        snap.forEach(d => recipients.push(d.id));
      }
    } else {
      const ids = Array.isArray(target) ? target : (target ? [String(target)] : []);
      // Separate raw Telegram chat IDs (all digits) from Firestore player IDs
      for (const id of ids) {
        if (/^-?\d+$/.test(id)) {
          // Raw Telegram chat ID — send direct, skip player lookup
          if (!channel || channel === 'telegram' || channel === 'both')
            await sendTelegram(id, message).catch(()=>{});
        } else {
          recipients.push(id);
        }
      }
    }

    // For Firestore player IDs, use _notifyPlayer so all channels fire
    const deliveryReport = [];
    for (const pid of recipients) {
      const doEmail    = !channel || channel === 'email'    || channel === 'both';
      const doTelegram = !channel || channel === 'telegram' || channel === 'both';
      const snap = await db.collection('players').doc(pid).get();
      if (!snap.exists) {
        console.warn(`[CEE] sendNotification: player ${pid} not found in Firestore`);
        deliveryReport.push({ pid, error: 'Player not found in Firestore' });
        continue;
      }
      const p = snap.data();
      const report = { pid, name: p.clubName || p.gameName || pid, telegram: null, email: null };

      // Telegram
      if (doTelegram) {
        if (!p.telegramChatId) {
          report.telegram = 'skipped — not linked (player must message the bot with /start)';
        } else {
          const tgR = await sendTelegram(p.telegramChatId, message);
          report.telegram = (tgR && tgR.ok) ? 'sent' : ('failed — ' + (tgR && tgR.description || 'unknown error'));
          if (!tgR || !tgR.ok) console.warn(`[CEE] Telegram failed for ${pid}:`, tgR);
        }
      }

      // Email
      if (doEmail) {
        if (!p.email) {
          report.email = 'skipped — no email on player record';
        } else {
          const emR = await sendEmail(p.email, subj, html);
          report.email = emR.success ? 'sent' : ('failed — ' + (emR.error || 'unknown error'));
          if (!emR.success) console.warn(`[CEE] Email failed for ${pid}:`, emR.error);
        }
      }

      // WhatsApp relay
      if (p.whatsappNumber) await _queueWhatsAppRelay(null, pid, p, message).catch(()=>{});

      const actualStatus = (report.telegram === 'sent' || report.email === 'sent') ? 'sent' : 'failed';
      await logNotif(null, pid, channel||'both', eventType||'MANUAL', actualStatus, null,
        { messageText: message, emailSubject: subj, deliveryDetail: report }).catch(()=>{});
      deliveryReport.push(report);
    }

    // Build summary for the admin UI
    const sent    = deliveryReport.filter(r => r.telegram === 'sent' || r.email === 'sent').length;
    const skipped = deliveryReport.filter(r => r.telegram && r.telegram.startsWith('skipped') && r.email && r.email.startsWith('skipped')).length;
    const failed  = deliveryReport.length - sent - skipped;
    console.log(`[CEE] Manual notification: ${sent} delivered, ${skipped} skipped (not linked), ${failed} failed`);
    return res.json({ success: true, sent, skipped, failed, report: deliveryReport });
  } catch(e) { return res.status(500).json({ success: false, message: e.message }); }
});

// GET /checkTelegramBot — verifies bot token is working (used by admin status panel)
app.get('/checkTelegramBot', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const token = env.telegram && env.telegram.token;
  if (!token) return res.json({ ok: false, description: 'TELEGRAM_TOKEN not set in Railway environment variables.' });
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    const d = await r.json();
    return res.json(d);
  } catch(e) { return res.status(500).json({ ok: false, description: e.message }); }
});

// POST /setTelegramWebhook — sets the Telegram webhook URL
app.post('/setTelegramWebhook', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const token = env.telegram && env.telegram.token;
  if (!token) return res.json({ ok: false, description: 'TELEGRAM_TOKEN not set in Railway.' });
  const { webhookUrl } = req.body;
  const url = webhookUrl || `${process.env.RAILWAY_PUBLIC_DOMAIN ? 'https://'+process.env.RAILWAY_PUBLIC_DOMAIN : ''}/telegramWebhook`;
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/setWebhook?url=${encodeURIComponent(url)}`);
    const d = await r.json();
    return res.json(d);
  } catch(e) { return res.status(500).json({ ok: false, description: e.message }); }
});

app.post('/retryNotification', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { notifId } = req.body;
  if (!notifId) return res.status(400).json({ success:false });
  try {
    const doc=await db.collection('notifications').doc(notifId).get();
    if (!doc.exists) return res.status(404).json({ success:false });
    const n=doc.data();
    const retryCount=(n.retryCount||0)+1;
    if (retryCount>3){ await doc.ref.update({status:'permanently_failed',retryCount}); return res.json({ success:false, message:'Max retries exceeded.' }); }
    if (n.lastRetryAt) {
      const minsSinceLast=nowWAT().diff(fromTS(n.lastRetryAt),'minutes').minutes;
      const minDelay=Math.pow(2,retryCount-1);
      if (minsSinceLast<minDelay) return res.json({ success:false, message:`Too soon. Wait ${Math.ceil(minDelay-minsSinceLast)} more minute(s).` });
    }
    const pd=await db.collection('players').doc(n.recipientId).get();
    if (pd.exists) {
      const p=pd.data();
      const subject=`CEE — Notification Retry (${n.eventType})`;
      const html=`<p>This is a retry of a previously failed notification: <strong>${n.eventType}</strong></p>`;
      if (n.channel!=='telegram'&&p.email&&p.notificationsEmail!==false) await sendEmail(p.email,subject,html);
      if (n.channel!=='email'&&p.telegramChatId&&p.notificationsTelegram!==false) await sendTelegram(p.telegramChatId,`📨 Retry: ${n.eventType}`);
    }
    await doc.ref.update({ status:'sent', retryCount, lastRetryAt:admin.firestore.FieldValue.serverTimestamp() });
    return res.json({ success:true, retryCount });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
});

app.post('/retryAllFailed', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const failed=await db.collection('notifications').where('status','==','failed').where('retryCount','<',3).get();
  const batch=db.batch();
  failed.forEach(doc => batch.update(doc.ref,{status:'pending'}));
  await batch.commit();
  return res.json({ success:true, count:failed.size });
});

app.post('/testNotification', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { channel, subscription } = req.body; // optional: channel='email'|'telegram'|'push'|'all'
  const results = { email: null, telegram: null, push: null };
  const doAll      = !channel || channel === 'all';
  const doEmail    = doAll || channel === 'email';
  const doTelegram = doAll || channel === 'telegram';
  const doPush     = doAll || channel === 'push';

  // ── Email ──────────────────────────────────────────────────────────────
  if (doEmail) {
    try {
      if (_brevoAccounts.length === 0) {
        results.email = { ok:false, error:'No Brevo accounts configured. Add BREVO_KEY_1 + BREVO_FROM_1 in Railway → Variables. Sign up free at app.brevo.com (300 emails/day, no domain needed).' };
      } else {
        const testTo = env.admin && env.admin.email;
        if (!testTo) {
          results.email = { ok:false, error:'ADMIN_EMAIL not set in Railway — needed to know where to send the test email.' };
        } else {
          const acct = _pickBrevoAccount();
          if (!acct) {
            results.email = { ok:false, error:`All ${_brevoAccounts.length} Brevo account(s) have hit their daily limit. Wait until midnight WAT or add another account.` };
          } else {
            const info = await sendEmail(testTo,
              'CEE — Test Email ✅',
              `<p>✅ Brevo email is working correctly!</p><div class="hl">Sent from: ${acct.from}<br>Account ${_brevoAccounts.indexOf(acct)+1} of ${_brevoAccounts.length} — ${acct.sentToday} emails used today</div>`
            );
            results.email = info.success
              ? { ok: true, to: testTo }
              : { ok: false, error: info.error };
          }
        }
      }
    } catch(e) {
      results.email = { ok: false, error: e.message };
    }
  }

  // ── Telegram ───────────────────────────────────────────────────────────
  if (doTelegram) {
    try {
      if (!env.telegram || !env.telegram.token) {
        results.telegram = { ok:false, error:'TELEGRAM_TOKEN not set in Railway environment variables.' };
      } else if (!env.telegram.admin_chat_id) {
        results.telegram = { ok:false, error:'TELEGRAM_ADMIN_CHAT_ID not set in Railway environment variables.' };
      } else {
        const r = await sendTelegram(env.telegram.admin_chat_id,
          '✅ <b>CEE Telegram Test</b>\n\nYour Telegram notifications are working correctly.'
        );
        if (r && r.ok) {
          results.telegram = { ok:true, chat_id:env.telegram.admin_chat_id };
        } else {
          results.telegram = { ok:false, error: (r && r.description) || 'Telegram API returned an error. Check TELEGRAM_TOKEN is valid.' };
        }
      }
    } catch(e) {
      results.telegram = { ok:false, error:e.message };
    }
  }

  // ── Web Push ───────────────────────────────────────────────────────────
  if (doPush) {
    try {
      if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
        results.push = { ok:false, error:'VAPID_PUBLIC_KEY or VAPID_PRIVATE_KEY not set in Railway environment variables.' };
      } else if (!subscription) {
        results.push = { ok:false, error:'No push subscription provided. Subscribe in Player Hub Settings tab first.' };
      } else {
        const sub = typeof subscription === 'string' ? JSON.parse(subscription) : subscription;
        const r = await _sendWebPush(sub, {
          title: '⚡ CEE — Test Notification',
          body:  '✅ Web Push is working correctly!',
          eventType: 'TEST',
          urgency: 'normal'
        });
        results.push = r.ok ? { ok:true } : { ok:false, error: r.error || 'Push failed' };
      }
    } catch(e) {
      results.push = { ok:false, error:e.message };
    }
  }

  const allOk = (!doEmail || (results.email && results.email.ok))
    && (!doTelegram || (results.telegram && results.telegram.ok))
    && (!doPush || (results.push && results.push.ok));
  return res.json({ success: allOk, results });
});

// GET /diagnoseNotifications — checks all channels without sending, returns full config status
app.get('/diagnoseNotifications', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const diag = {
    email: {
      configured: _brevoAccounts.length > 0,
      accountCount: _brevoAccounts.length,
      accounts: _brevoAccounts.map(a => ({ from: a.from, sentToday: a.sentToday, remaining: Math.max(0, 295 - a.sentToday) })),
      dailyCapacity: _brevoAccounts.length * 295,
      adminEmailSet: !!(env.admin && env.admin.email),
      source: process.env.BREVO_KEY_1 ? 'railway_env' : (_brevoAccounts.length > 0 ? 'firestore_adminSettings' : 'not_configured')
    },
    telegram: {
      tokenConfigured: !!(env.telegram && env.telegram.token),
      adminChatIdSet:  !!(env.telegram && env.telegram.admin_chat_id),
      tokenPreview: env.telegram && env.telegram.token ? env.telegram.token.substring(0,8) + '...' : null,
      source: process.env.TELEGRAM_TOKEN ? 'railway_env' : (env.telegram && env.telegram.token ? 'firestore_adminSettings' : 'not_configured'),
      webhookNote: 'Webhook must be set via admin panel → Season Clock → Set Telegram Webhook button'
    },
    whatsapp: {
      note: 'WhatsApp notifications use the admin as a relay. Players with whatsappNumber set will have messages queued in the notification log for admin to forward.'
    },
    webPush: {
      vapidConfigured: !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY),
      publicKeyPreview: VAPID_PUBLIC_KEY ? VAPID_PUBLIC_KEY.substring(0, 12) + '...' : null,
      note: 'Players must visit the site and click "Enable Push Notifications" in their Player Hub to subscribe.'
    }
  };

  try {
    const sid = await getSeasonId();
    if (sid) {
      const players = await getPlayers(sid);
      diag.players = {
        total:            players.length,
        withEmail:        players.filter(p=>p.email).length,
        withTelegram:     players.filter(p=>p.telegramChatId).length,
        withWhatsapp:     players.filter(p=>p.whatsappNumber).length,
        withPush:         players.filter(p=>p.pushSubscription).length,
        emailOptedOut:    players.filter(p=>p.notificationsEmail===false).length,
        telegramOptedOut: players.filter(p=>p.notificationsTelegram===false).length,
        pushOptedOut:     players.filter(p=>p.notificationsPush===false).length
      };
    }
  } catch(e) { diag.playersError = e.message; }

  diag.suggestions = [];
  if (!diag.email.configured)
    diag.suggestions.push('No Brevo accounts configured. Add BREVO_KEY_1 + BREVO_FROM_1 in Railway → Variables. Sign up free at app.brevo.com — 300 emails/day per account, no domain needed.');
  if (diag.email.configured && diag.email.accountCount < 2)
    diag.suggestions.push('Only 1 Brevo account configured (295 emails/day). Add BREVO_KEY_2 + BREVO_FROM_2 with a second account to reach 590 emails/day.');
  if (!diag.telegram.tokenConfigured)
    diag.suggestions.push('Set TELEGRAM_TOKEN in Railway → Variables (get it from @BotFather on Telegram)');
  if (!diag.telegram.adminChatIdSet)
    diag.suggestions.push('Set TELEGRAM_ADMIN_CHAT_ID in Railway — this is YOUR personal Telegram chat ID (send /start to @userinfobot to find it)');
  if (!diag.webPush.vapidConfigured)
    diag.suggestions.push('Set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY in Railway to enable web push notifications — these were generated for you, check the session notes.');
  if (diag.players && diag.players.withPush === 0 && diag.webPush.vapidConfigured)
    diag.suggestions.push('VAPID is configured but no players have subscribed yet. They need to click "Enable Push Notifications" in the Player Hub Settings tab.');
  if (diag.players && diag.players.total > 0 && diag.players.withTelegram === 0)
    diag.suggestions.push(`⚠️ ${diag.players.total} registered player(s) but NONE have linked Telegram yet. They must message your bot with /start followed by their Player ID or gaming tag. Until they link, Telegram notifications go nowhere.`);
  if (diag.players && diag.players.total > 0 && diag.players.withEmail === 0)
    diag.suggestions.push(`⚠️ ${diag.players.total} registered player(s) but none have email in their profile. Check that registration form email field is saving correctly.`);
  if (diag.players && diag.players.withTelegram > 0 && diag.players.withTelegram < diag.players.total)
    diag.suggestions.push(`${diag.players.withTelegram} of ${diag.players.total} players have linked Telegram. Remaining ${diag.players.total - diag.players.withTelegram} players will NOT receive Telegram notifications until they message the bot with /start.`);

  // Check if webhook is set — this is the most common reason Telegram linking fails
  if (diag.telegram.tokenConfigured) {
    try {
      const whSnap = await fetch(`https://api.telegram.org/bot${env.telegram.token}/getWebhookInfo`);
      const whData = await whSnap.json();
      if (whData.ok && whData.result) {
        const wh = whData.result;
        diag.telegram.webhookUrl = wh.url || null;
        diag.telegram.webhookPending = wh.pending_update_count || 0;
        diag.telegram.webhookLastError = wh.last_error_message || null;
        if (!wh.url) {
          diag.suggestions.push('🔴 CRITICAL: Telegram webhook is NOT set. Players cannot link their accounts and you will not receive notifications. Click "Set Webhook" in the admin panel → Season Clock → Notifications tab.');
        } else if (wh.last_error_message) {
          diag.suggestions.push(`⚠️ Telegram webhook has errors: "${wh.last_error_message}". This may be causing message delivery failures.`);
        } else if (wh.pending_update_count > 10) {
          diag.suggestions.push(`ℹ️ Telegram has ${wh.pending_update_count} pending unprocessed updates. Check Railway logs for errors.`);
        }
      }
    } catch(e) { /* non-fatal webhook check */ }
  }

  return res.json({ ok: true, diag });
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /scheduleReplay
// ═══════════════════════════════════════════════════════════════════════════
app.post('/scheduleReplay', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { fixtureId, seasonId } = req.body;
  if (!fixtureId||!seasonId) return res.status(400).json({ success:false, message:'Missing fields' });
  try {
    const fixDoc=await db.collection('fixtures').doc(fixtureId).get();
    if (!fixDoc.exists) return res.json({ success:false, message:'Fixture not found' });
    const fix=fixDoc.data();
    await fixDoc.ref.update({status:'void'});
    const now=nowWAT(); let candidate=now.plus({days:1});
    while (![5,6,7].includes(candidate.weekday)) candidate=candidate.plus({days:1});
    const openH=candidate.weekday===5?15:13;
    const winOpen=candidate.set({hour:openH,minute:0,second:0,millisecond:0});
    const winClose=candidate.set({hour:23,minute:59,second:59,millisecond:0});
    const newFix=await db.collection('fixtures').add({
      seasonId, phase:'replay', originalFixtureId:fixtureId,
      playerAId:fix.playerAId, playerBId:fix.playerBId,
      matchday:fix.matchday+0.5, week:fix.week, status:'scheduled',
      windowOpenTime:toTS(winOpen), windowCloseTime:toTS(winClose),
      createdAt:admin.firestore.FieldValue.serverTimestamp(), done:false, adminApproved:false
    });
    await audit('REPLAY_SCHEDULED',newFix.id,'fixture',`Replay of ${fixtureId} scheduled`);
    await _sendMatchNotifications('REPLAY_SCHEDULED',newFix.id,fix.playerAId,fix.playerBId,seasonId);
    return res.json({ success:true, newFixtureId:newFix.id });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /requestDoubleConsent — NOTIF-02: respects notification preferences
// ═══════════════════════════════════════════════════════════════════════════
app.post('/requestDoubleConsent', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { fixtureId, playerAId, playerBId } = req.body;
  if (!fixtureId||!playerAId||!playerBId) return res.status(400).json({ success:false });
  try {
    const expiresAt=toTS(nowWAT().plus({hours:2}));
    await db.collection('fixtures').doc(fixtureId).update({
      doubleConsentRequestedAt:admin.firestore.FieldValue.serverTimestamp(),
      doubleConsentExpiresAt:expiresAt, doubleConsentA:false, doubleConsentB:false
    });
    for (const pid of [playerAId,playerBId]) {
      const pd=await db.collection('players').doc(pid).get();
      if (!pd.exists) continue;
      const p=pd.data();
      const msg=`⚠️ <b>Double Fixture Consent Request</b>\n\nYou've been asked to play a second fixture on the same matchday (Fixture ID: ${fixtureId}).\n\nBoth players must agree within 2 hours. Reply via the CEE Player Hub.`;
      if (p.telegramChatId&&p.notificationsTelegram!==false) await sendTelegram(p.telegramChatId,msg);
      if (p.email&&p.notificationsEmail!==false) await sendEmail(p.email,'CEE — Double Fixture Consent',
        `<p>⚠️ You have been asked to play a second fixture on the same matchday.</p>
         <div class="hl">Fixture ID: ${fixtureId}</div>
         <p>Both players must agree via the CEE Player Hub within <strong>2 hours</strong> or the request expires.</p>`);
      await logNotif(fixtureId,pid,'both','DOUBLE_CONSENT_REQUEST','sent');
    }
    return res.json({ success:true });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /grantDoubleConsent
// ═══════════════════════════════════════════════════════════════════════════
app.post('/grantDoubleConsent', async (req, res) => {
  const { fixtureId, playerId } = req.body;
  if (!fixtureId||!playerId) return res.status(400).json({ success:false });
  try {
    const fixRef=db.collection('fixtures').doc(fixtureId);
    const fixSnap=await fixRef.get();
    if (!fixSnap.exists) return res.status(404).json({ success:false });
    const f=fixSnap.data();
    if (!f.doubleConsentRequestedAt) return res.json({ success:false, message:'No active consent request.' });
    if (f.doubleConsentExpired) return res.json({ success:false, message:'Consent request has expired.' });
    if (f.doubleConsentA&&f.doubleConsentB) return res.json({ success:false, message:'Both players already consented.' });
    const isA=f.playerAId===playerId, isB=f.playerBId===playerId;
    if (!isA&&!isB) return res.json({ success:false, message:'Not a participant in this fixture.' });
    const updateKey=isA?'doubleConsentA':'doubleConsentB';
    await fixRef.update({[updateKey]:true});
    const nowA=isA?true:f.doubleConsentA, nowB=isB?true:f.doubleConsentB;
    if (nowA&&nowB) {
      for (const pid of [f.playerAId,f.playerBId]) {
        if (!pid) continue;
        const pd=await db.collection('players').doc(pid).get();
        if (!pd.exists) continue;
        const p=pd.data();
        const msg=`✅ <b>Double fixture consent granted!</b>\nBoth players agreed to play a second fixture. Your admin will schedule it shortly.`;
        if (p.telegramChatId&&p.notificationsTelegram!==false) await sendTelegram(p.telegramChatId,msg);
        if (p.email&&p.notificationsEmail!==false) await sendEmail(p.email,'CEE — Double Fixture Consent Granted',
          `<p>✅ Both you and your opponent have agreed to play a second fixture on the same matchday.</p>
           <p>The admin will schedule the additional match shortly.</p>`);
        await logNotif(fixtureId,pid,'both','DOUBLE_CONSENT_GRANTED','sent');
      }
      const adminChat=env.telegram&&env.telegram.admin_chat_id;
      if (adminChat) await sendTelegram(adminChat,`✅ <b>Double consent granted</b>\nFixture: ${fixtureId}\nBoth players agreed.`);
    }
    return res.json({ success:true, bothGranted:nowA&&nowB });
  } catch(e){ console.error('[CEE] grantDoubleConsent:',e); return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /resolveDispute — AUTH-02: validates non-negative integer goals
// ═══════════════════════════════════════════════════════════════════════════
app.post('/resolveDispute', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { disputeId, verdict, adminNote, fixtureId, playerAGoals, playerBGoals } = req.body;
  if (!disputeId||!verdict||!fixtureId) return res.status(400).json({ success:false, message:'Missing fields' });
  try {
    const disputeRef=db.collection('disputes').doc(disputeId);
    const disputeDoc=await disputeRef.get();
    if (!disputeDoc.exists) return res.status(404).json({ success:false, message:'Dispute not found' });
    const d=disputeDoc.data();
    if (d.status!=='open') return res.json({ success:false, message:'Dispute is not open.' });
    const goalsA=(Number.isInteger(playerAGoals)&&playerAGoals>=0)?playerAGoals:null;
    const goalsB=(Number.isInteger(playerBGoals)&&playerBGoals>=0)?playerBGoals:null;
    if (goalsA===null||goalsB===null) return res.status(400).json({ success:false, message:'Goals must be non-negative integers.' });

    await disputeRef.update({ status:'resolved', verdict, adminNote:adminNote||'',
      resolvedAt:admin.firestore.FieldValue.serverTimestamp(), resolvedBy:'admin' });
    await db.collection('fixtures').doc(fixtureId).update({
      status:'approved', adminApproved:true, done:true,
      playerAGoals:goalsA, playerBGoals:goalsB, result:verdict,
      disputeResolvedAt:admin.firestore.FieldValue.serverTimestamp()
    });
    await audit('DISPUTE_RESOLVED',fixtureId,'fixture',`Admin resolved ${disputeId}: ${verdict}`,'open','resolved');

    const pA=d.playerAId?(await db.collection('players').doc(d.playerAId).get()):null;
    const pB=d.playerBId?(await db.collection('players').doc(d.playerBId).get()):null;
    const html=`<p>⚖️ The dispute for your match has been <strong>resolved</strong> by the admin.</p>
      <div class="hl">Verdict: ${verdict}</div>
      <p>Final result: ${goalsA}–${goalsB}</p>${adminNote?`<p>Admin note: ${adminNote}</p>`:''}`;
    const tg=`⚖️ <b>Dispute Resolved</b>\nVerdict: ${verdict}\nResult: ${goalsA}–${goalsB}`;
    for (const pd of [pA,pB]) {
      if (!pd||!pd.exists) continue;
      const p=pd.data();
      if (p.email&&p.notificationsEmail!==false) await sendEmail(p.email,'CEE — Dispute Resolved',html);
      if (p.telegramChatId&&p.notificationsTelegram!==false) await sendTelegram(p.telegramChatId,tg);
      await logNotif(fixtureId,pd.id,'both','DISPUTE_RESOLVED','sent');
    }
    const seasonId=d.seasonId||(await getSeasonId());
    if (seasonId) { await _recalcStandingsInternal(seasonId); await _checkKnockoutQualification(seasonId); }
    return res.json({ success:true });
  } catch(e){ console.error('[CEE] resolveDispute:',e); return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /approveRegistration | /rejectRegistration
// ═══════════════════════════════════════════════════════════════════════════
app.post('/approveRegistration', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { regId, seasonId, pin } = req.body;
  if (!regId||!seasonId) return res.status(400).json({ success:false, message:'Missing fields' });
  try {
    const regDoc=await db.collection('registrations').doc(regId).get();
    if (!regDoc.exists) return res.status(404).json({ success:false, message:'Registration not found' });
    const reg=regDoc.data();
    if (reg.status==='approved') return res.json({ success:false, message:'Already approved.' });
    const playerPin=pin||String(Math.floor(1000+Math.random()*9000));
    const pinHash=await bcrypt.hash(playerPin,12);

    // ── Identity linking: find all previous player docs matching email or phone ──
    // TIER 1: Check the fast returningPlayersMap (built at season transition) — one read.
    // TIER 2: Fall back to collection queries (works even without a map, e.g. first season).
    // This powers cross-season memory, integrity score continuity, and playstyle carry-forward.
    const linkedPreviousPlayerIds = [];
    let inheritedIntegrityScore   = 100;
    let inheritedPlaystyleNote    = null;
    try {
      const emailKey = reg.email.toLowerCase().trim();
      const cleanPhone = reg.phone ? String(reg.phone).replace(/\D/g, '') : null;
      let foundViaMap = false;

      // ── TIER 1: Fast returning players map lookup ─────────────────────────
      const mapDoc = await db.collection('config').doc('returningPlayersMap').get();
      if (mapDoc.exists) {
        const map = mapDoc.data();
        const byEmail = map.byEmail || {};
        const byPhone = map.byPhone || {};
        const foundIds = new Set();
        if (byEmail[emailKey]) foundIds.add(byEmail[emailKey]);
        if (cleanPhone && cleanPhone.length >= 8 && byPhone[cleanPhone]) foundIds.add(byPhone[cleanPhone]);
        foundIds.forEach(id => {
          if (!linkedPreviousPlayerIds.includes(id)) linkedPreviousPlayerIds.push(id);
        });
        if (linkedPreviousPlayerIds.length > 0) foundViaMap = true;
      }

      // ── TIER 2: Full collection query fallback ────────────────────────────
      if (!foundViaMap) {
        const linkQueries = [
          db.collection('players').where('email', '==', emailKey).get()
        ];
        if (cleanPhone && cleanPhone.length >= 8) {
          linkQueries.push(db.collection('players').where('phone', '==', cleanPhone).get());
        }
        const linkResults = await Promise.allSettled(linkQueries);
        linkResults.forEach(result => {
          if (result.status !== 'fulfilled') return;
          result.value.forEach(d => {
            if (d.data().seasonId !== seasonId && !linkedPreviousPlayerIds.includes(d.id)) {
              linkedPreviousPlayerIds.push(d.id);
            }
          });
        });
      }
      if (linkedPreviousPlayerIds.length > 0) {
        // Find the most recent linked player (highest season number)
        let mostRecentDoc = null;
        for (const lid of linkedPreviousPlayerIds) {
          const ld = await db.collection('players').doc(lid).get();
          if (!ld.exists) continue;
          const ldata = ld.data();
          if (!mostRecentDoc ||
              (ldata.seasonId || '').localeCompare(mostRecentDoc.seasonId || '') > 0) {
            mostRecentDoc = ldata;
          }
        }
        if (mostRecentDoc) {
          // Carry forward integrity score — returning player keeps their record
          if (mostRecentDoc.integrityScore != null) {
            // Slight reset toward 100 between seasons (forgiveness factor)
            // Score < 70 gets bumped to 70 as a season-grace reset, but not above
            inheritedIntegrityScore = mostRecentDoc.integrityScore < 70
              ? Math.min(70, mostRecentDoc.integrityScore + 10)
              : mostRecentDoc.integrityScore;
          }
          // Build a note about returning player for admin awareness
          const prevSeason = mostRecentDoc.seasonId || 'unknown season';
          const prevTag    = mostRecentDoc.clubName || mostRecentDoc.gameName || 'unknown tag';
          inheritedPlaystyleNote = `Returning player. Previously played as ${prevTag} in ${prevSeason}.`;
          console.log(`[CEE] Identity link: ${reg.gameName} -> linked to ${linkedPreviousPlayerIds.length} prev player(s). Inherited integrity: ${inheritedIntegrityScore}`);
        }
      }
    } catch(linkErr) {
      console.error('[CEE] Identity linking error (non-fatal):', linkErr.message);
    }

    // Auto-assign pot based on real eFootball 2026 squad strength tiers
    // P1: 3250+ (top 5-10%, Big Time/Epic Booster cards)
    // P2: 3150+ (standard competitive, the 3150 average)
    // P3: 3000+ (developing, below average)
    // P4: <3000  (new player / themed / authentic squad)
    const regStrength = Number(reg.strength) || 0;
    const autoPot = reg.pot ? Number(reg.pot) :
      regStrength >= 3250 ? 1 :
      regStrength >= 3150 ? 2 :
      regStrength >= 3000 ? 3 : 4;

    const playerRef=await db.collection('players').add({
      seasonId, gameName:reg.gameName||'', clubName:reg.clubName||'',
      initials:reg.initials||(reg.gameName||'').substring(0,2).toUpperCase(),
      email:reg.email||'', telegramUsername:reg.telegramUsername||'',
      phone: reg.phone ? String(reg.phone).replace(/\D/g,'') : null,
      telegramChatId:reg.telegramChatId||null, notificationsEmail:true, notificationsTelegram:true,
      registrationId:regId, legacyId:null,
      strength: regStrength, pot: autoPot, fromReg: true,
      stats:{pts:0,mp:0,pld:0,w:0,d:0,l:0,gf:0,ga:0,gd:0,goals:0},
      rank:null, knockoutStatus:null,
      // Identity linking fields
      linkedPreviousPlayerIds: linkedPreviousPlayerIds.length > 0 ? linkedPreviousPlayerIds : null,
      integrityScore: inheritedIntegrityScore,
      returningPlayer: linkedPreviousPlayerIds.length > 0,
      returningPlayerNote: inheritedPlaystyleNote,
      createdAt:admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection('playerSecrets').doc(playerRef.id).set(
      {pinHash,pinFailAttempts:0,pinLockoutUntil:null,pinLockoutCount:0});
    await regDoc.ref.update({status:'approved',playerId:playerRef.id,approvedAt:admin.firestore.FieldValue.serverTimestamp()});

    // ── Update returningPlayersMap with this new player for future seasons ───────
    // So the NEXT season can find this player via map lookup too
    try {
      const mapUpdate = {};
      if (reg.email) mapUpdate[`byEmail.${reg.email.toLowerCase().trim()}`] = playerRef.id;
      const cleanPhoneNew = reg.phone ? String(reg.phone).replace(/\D/g,'') : null;
      if (cleanPhoneNew && cleanPhoneNew.length >= 8) mapUpdate[`byPhone.${cleanPhoneNew}`] = playerRef.id;
      if (Object.keys(mapUpdate).length > 0) {
        await db.collection('config').doc('returningPlayersMap').set(mapUpdate, { merge: true });
      }
    } catch(mapErr) { console.error('[CEE] returningPlayersMap update error (non-fatal):', mapErr.message); }

    // Admin notification if returning player was found
    if (linkedPreviousPlayerIds.length > 0) {
      const adminChat = env.telegram && env.telegram.admin_chat_id;
      if (adminChat) sendTelegram(adminChat,
        `RETURNING PLAYER DETECTED\n${reg.gameName} (${reg.email})\nLinked to ${linkedPreviousPlayerIds.length} prev season player(s)\nInherited integrity score: ${inheritedIntegrityScore}/100\n${inheritedPlaystyleNote || ''}`
      ).catch(()=>{});
    }
    if (reg.email) {
      await sendEmail(reg.email,'CEE — Registration Approved 🎮',
        `<p>🎉 <strong>Your registration has been approved!</strong></p>
         <p>Welcome to Campus eSports Elite. Here are your login credentials:</p>
         <div class="hl" style="font-size:16px">
           <strong>Gaming Tag:</strong> ${reg.gameName||reg.clubName}<br>
           <strong>PIN:</strong> <span style="font-size:24px;font-weight:700;letter-spacing:.2em">${playerPin}</span>
         </div>
         <p>⚠️ <strong>Keep your PIN private.</strong> You'll use it to access the CEE Player Hub.</p>
         <p>Log in at the CEE website to view fixtures and submit results.</p>`);
    }
    await logNotif(null,playerRef.id,'email','REGISTRATION_APPROVED','sent');
    await audit('REGISTRATION_APPROVED',regId,'registration',`Player created: ${playerRef.id}`);
    // Return full player data so frontend immediately updates Players tab
    const newPlayerDoc = await playerRef.get();
    const playerData = newPlayerDoc.exists ? { _id: newPlayerDoc.id, ...newPlayerDoc.data() } : null;
    return res.json({ success:true, playerId: playerRef.id, player: playerData });
  } catch(e){ console.error('[CEE] approveRegistration:',e); return res.status(500).json({ success:false, message:e.message }); }
});

app.post('/rejectRegistration', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { regId, reason } = req.body;
  if (!regId) return res.status(400).json({ success:false, message:'Missing regId' });
  try {
    const regDoc=await db.collection('registrations').doc(regId).get();
    if (!regDoc.exists) return res.status(404).json({ success:false });
    const reg=regDoc.data();
    if (reg.status==='rejected') return res.json({ success:false, message:'Already rejected.' });
    await regDoc.ref.update({ status:'rejected', rejectionReason:reason||'', rejectedAt:admin.firestore.FieldValue.serverTimestamp() });
    if (reg.email) {
      await sendEmail(reg.email,'CEE — Registration Update',
        `<p>We regret to inform you that your registration for <strong>Campus eSports Elite</strong> was not approved at this time.</p>
         ${reason?`<div class="hl">Reason: ${reason}</div>`:''}
         <p>Please contact the league admin if you have questions.</p>`);
    }
    await logNotif(null,regId,'email','REGISTRATION_REJECTED','sent');
    await audit('REGISTRATION_REJECTED',regId,'registration',reason||'No reason given');
    return res.json({ success:true });
  } catch(e){ console.error('[CEE] rejectRegistration:',e); return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /declareForceMajeure | /liftForceMajeure
// ═══════════════════════════════════════════════════════════════════════════
app.post('/declareForceMajeure', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { seasonId, reason } = req.body;
  if (!seasonId) return res.status(400).json({ success:false });
  try {
    await db.collection('seasons').doc(seasonId).update({
      forceMajeure:true, forceMajeureReason:reason||'',
      forceMajeureDeclaredAt:admin.firestore.FieldValue.serverTimestamp()
    });
    _invalidateSeasonIdCache(); // season state changed — flush 5-min TTL cache
    const open=await db.collection('fixtures').where('seasonId','==',seasonId)
      .where('status','in',['window_open','ready_pending','in_progress']).get();
    const batch=db.batch();
    open.forEach(doc => batch.update(doc.ref,{statusBeforeFM:doc.data().status,status:'paused_fm'}));
    await batch.commit();
    const players=await getPlayers(seasonId);
    const msg=`🚨 <b>Force Majeure Declared</b>\nAll match windows have been paused.\n${reason?`Reason: ${reason}`:'Admin will reschedule affected fixtures.'}`;
    await Promise.allSettled(players.map(p => {
      const s=[];
      if (p.telegramChatId) s.push(sendTelegram(p.telegramChatId,msg).catch(()=>{}));
      if (p.email) s.push(sendEmail(p.email,'CEE — Force Majeure Declared',
        `<p>🚨 <strong>Force Majeure has been declared</strong> by the league administrator.</p>
         ${reason?`<div class="hl">Reason: ${reason}</div>`:''}
         <p>All match windows have been paused. You will be notified when normal scheduling resumes.</p>`
      ).catch(()=>{}));
      return Promise.allSettled(s);
    }));
    await audit('FORCE_MAJEURE_DECLARED',seasonId,'season',reason||'No reason given');
    return res.json({ success:true, pausedFixtures:open.size });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
});

app.post('/liftForceMajeure', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { seasonId } = req.body;
  if (!seasonId) return res.status(400).json({ success:false });
  try {
    await db.collection('seasons').doc(seasonId).update({
      forceMajeure:false, forceMajeureLiftedAt:admin.firestore.FieldValue.serverTimestamp()
    });
    _invalidateSeasonIdCache(); // season state changed — flush 5-min TTL cache
    const paused=await db.collection('fixtures').where('seasonId','==',seasonId).where('status','==','paused_fm').get();
    const batch=db.batch();
    paused.forEach(doc => batch.update(doc.ref,{status:doc.data().statusBeforeFM||'window_open',statusBeforeFM:null}));
    await batch.commit();
    const players=await getPlayers(seasonId);
    const msg=`✅ <b>Force Majeure Lifted</b>\nNormal match scheduling has resumed. Check your fixtures.`;
    await Promise.allSettled(players.map(p => {
      const s=[];
      if (p.telegramChatId) s.push(sendTelegram(p.telegramChatId,msg).catch(()=>{}));
      if (p.email) s.push(sendEmail(p.email,'CEE — Force Majeure Lifted',
        `<p>✅ <strong>Force Majeure has been lifted.</strong> Normal match scheduling has resumed.</p>
         <p>Please check the CEE website for your updated fixture schedule.</p>`).catch(()=>{}));
      return Promise.allSettled(s);
    }));
    await audit('FORCE_MAJEURE_LIFTED',seasonId,'season','Force Majeure lifted, fixtures resumed');
    return res.json({ success:true, resumedFixtures:paused.size });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /recalculateStandings
// ═══════════════════════════════════════════════════════════════════════════
app.post('/recalculateStandings', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { seasonId:sid } = req.body;
  try {
    const seasonId=sid||(await getSeasonId());
    if (!seasonId) return res.status(400).json({ success:false, message:'No active season' });
    const standings=await _recalcStandingsInternal(seasonId);
    return res.json({ success:true, count:standings.length });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /verifyPaystackPayment — prevents frontend-bypass attacks
// ═══════════════════════════════════════════════════════════════════════════
app.post('/verifyPaystackPayment', async (req, res) => {
  const { reference } = req.body;
  if (!reference) return res.status(400).json({ success:false, message:'Missing payment reference' });
  const paystackSecret=env.paystack&&env.paystack.secret;
  if (!paystackSecret) {
    console.warn('[CEE] verifyPaystackPayment: PAYSTACK_SECRET not set — TEST MODE');
    return res.json({ success:true, verified:false, testMode:true, message:'Paystack secret not configured — skipping verification' });
  }
  try {
    const r=await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { method:'GET', headers:{ 'Authorization':`Bearer ${paystackSecret}`, 'Content-Type':'application/json' } });
    const data=await r.json();
    if (!data.status||!data.data) return res.status(502).json({ success:false, message:'Paystack verification failed' });
    const txn=data.data, paid=txn.status==='success';
    if (!paid) {
      await audit('PAYMENT_VERIFY_FAIL',reference,'payment',`Status: ${txn.status}`);
      return res.json({ success:false, message:`Payment status is "${txn.status}" — not confirmed.` });
    }
    await audit('PAYMENT_VERIFIED',reference,'payment',`Amount: ₦${(txn.amount/100).toLocaleString()}. Email: ${txn.customer&&txn.customer.email}`);
    return res.json({ success:true, verified:true, amount:txn.amount, currency:txn.currency,
      email:txn.customer&&txn.customer.email, metadata:txn.metadata, paidAt:txn.paid_at });
  } catch(e){ console.error('[CEE] verifyPaystackPayment:',e.message); return res.status(500).json({ success:false, message:'Server error: '+e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// POST /startNewSeason — archives current season and creates a fresh one
//
// What it does:
//   1. Validates current season is 'complete'
//   2. Archives everything to seasons_archive/{seasonId}
//   3. Creates a new season doc at seasons/season_N+1 with status 'pending'
//   4. Updates config/season.activeSeasonId
//   5. Invalidates the season ID cache
//   6. Notifies admin
// ═══════════════════════════════════════════════════════════════════════════
app.post('/startNewSeason', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { confirmedSeasonId } = req.body;
  // Admin must echo back the current seasonId as confirmation
  if (!confirmedSeasonId) return res.status(400).json({ success:false, message:'Provide confirmedSeasonId as a safeguard.' });

  try {
    const currentId = await getSeasonId();
    if (!currentId) return res.json({ success:false, message:'No active season found.' });
    if (currentId !== confirmedSeasonId)
      return res.json({ success:false, message:`Season ID mismatch. Expected "${currentId}", got "${confirmedSeasonId}".` });

    const seasonDoc = await db.collection('seasons').doc(currentId).get();
    if (!seasonDoc.exists) return res.json({ success:false, message:'Season document not found.' });
    const currentSeason = seasonDoc.data();

    if (currentSeason.status !== 'complete')
      return res.json({ success:false, message:`Season must be marked "complete" before starting a new one. Current status: "${currentSeason.status}".` });

    // ── Gather all data to archive ───────────────────────────────────────────────
    const [playersSnap, fixturesSnap, regsSnap, standingsSnap, matchStatsSnap] = await Promise.all([
      db.collection('players').where('seasonId','==',currentId).get(),
      db.collection('fixtures').where('seasonId','==',currentId).get(),
      db.collection('registrations').where('seasonId','==',currentId).get(),
      db.collection('standingsBroadcast').doc(currentId).get(),
      db.collection('matchStats').where('seasonId','==',currentId).get()
    ]);

    const players  = []; playersSnap.forEach(d => players.push({ _id:d.id, ...d.data() }));
    const fixtures = []; fixturesSnap.forEach(d => fixtures.push({ _id:d.id, ...d.data() }));
    const regs     = []; regsSnap.forEach(d => regs.push({ _id:d.id, ...d.data() }));
    const standings = standingsSnap.exists ? standingsSnap.data().standings : [];

    // ── Gather intelligence data for archive ─────────────────────────────────
    // playerProfile (playstyle fingerprints), scoutReports count, integrity scores
    const playerIds = players.map(p => p._id);

    // Fetch playstyle fingerprints for all players this season
    const playstyleProfiles = {};
    await Promise.allSettled(playerIds.map(async pid => {
      const pd = await db.collection('playerProfile').doc(pid).get();
      if (pd.exists) playstyleProfiles[pid] = pd.data();
    }));

    // Count scout reports and playerStatHistory entries
    const [scoutReportsSnap, statHistorySnap] = await Promise.all([
      db.collection('scoutReports').where('seasonId','==',currentId).get(),
      db.collection('playerStatHistory').where('seasonId','==',currentId).get()
    ]).catch(() => [{ size: 0 }, { size: 0 }]);

    // Capture integrity scores from player docs
    const integritySnapshot = {};
    players.forEach(p => {
      if (p.integrityScore != null) integritySnapshot[p._id] = p.integrityScore;
    });

    // ── Write comprehensive archive document ─────────────────────────────────
    const matchStatsDocs = [];
    matchStatsSnap.forEach(d => matchStatsDocs.push({ _id:d.id, ...d.data() }));

    await db.collection('seasons_archive').doc(currentId).set({
      seasonId:         currentId,
      seasonData:       currentSeason,
      players,
      fixtures,
      registrations:    regs,
      finalStandings:   standings,
      matchStats:       matchStatsDocs,
      playstyleProfiles,
      integritySnapshot,
      intelligenceStats: {
        scoutReports:    scoutReportsSnap.size || 0,
        statHistoryDocs: statHistorySnap.size  || 0,
      },
      archivedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // ── Build Returning Players Map ───────────────────────────────────────────
    // A flat lookup map stored at config/returningPlayersMap so the next season's
    // approveRegistration can find identity links with ONE read instead of
    // expensive full-collection queries. Indexed by email and phone.
    //
    // Structure: { byEmail: { 'email@x.com': 'playerId' }, byPhone: { '0801...': 'playerId' } }
    const byEmail = {};
    const byPhone = {};
    players.forEach(p => {
      if (p.email) byEmail[p.email.toLowerCase().trim()] = p._id;
      if (p.phone) {
        const cleanPhone = String(p.phone).replace(/\D/g, '');
        if (cleanPhone.length >= 8) byPhone[cleanPhone] = p._id;
      }
    });
    // Also fold in previous seasons' maps (cumulative — links go back multiple seasons)
    const existingMap = await db.collection('config').doc('returningPlayersMap').get();
    if (existingMap.exists) {
      const prev = existingMap.data();
      if (prev.byEmail) Object.assign(byEmail, prev.byEmail); // existing entries kept, new ones added
      if (prev.byPhone) Object.assign(byPhone, prev.byPhone);
    }
    await db.collection('config').doc('returningPlayersMap').set({
      byEmail,
      byPhone,
      lastUpdatedSeason: currentId,
      playerCount:       players.length,
      updatedAt:         admin.firestore.FieldValue.serverTimestamp()
    });
    console.log(`[CEE] Returning players map built: ${Object.keys(byEmail).length} emails, ${Object.keys(byPhone).length} phones`);

    // --- Determine new season number ---
    const currentNum = parseInt((currentId.replace('season_','') || '1'), 10);
    const newNum     = currentNum + 1;
    const newId      = `season_${newNum}`;

    // --- Create new season document ---
    await db.collection('seasons').doc(newId).set({
      status:      'pending',
      season:      newNum,
      format:      currentSeason.format || 20,
      createdAt:   admin.firestore.FieldValue.serverTimestamp(),
      createdBy:   'admin'
    });

    // --- Flip the active pointer ---
    await db.collection('config').doc('season').set({ activeSeasonId: newId }, { merge:true });

    // --- Bust the cache so next getSeasonId() picks up the new one ---
    _invalidateSeasonIdCache();

    // --- Notify admin ---
    const adminChat  = env.telegram && env.telegram.admin_chat_id;
    const adminEmail = env.admin    && env.admin.email;
    const returningCount = Object.keys(byEmail).length;
    const summary = `Season ${currentNum} archived (${players.length} players, ${fixtures.length} fixtures, ${scoutReportsSnap.size||0} scout reports).\nReturning players map built: ${returningCount} identities tracked.\nSeason ${newNum} created — status: Pending.\nOpen admin panel to configure registration dates and set status to Registration Open.`;
    if (adminChat)  await sendTelegram(adminChat, `🎮 <b>New Season Started!</b>\n\n${summary}`).catch(()=>{});
    if (adminEmail) await sendEmail(adminEmail, `CEE — Season ${newNum} Created`,
      `<p>🎮 <strong>Season ${newNum} has been created.</strong></p>
       <div class="hl">
         <strong>Season ${currentNum} archived:</strong> ${players.length} players, ${fixtures.length} fixtures<br>
         <strong>New season ID:</strong> ${newId}<br>
         <strong>Status:</strong> Pending
       </div>
       <p>Log into the admin panel → Season Clock to configure the new season.</p>`
    ).catch(()=>{});

    await audit('NEW_SEASON_STARTED', newId, 'season', `Archived season ${currentId} → created ${newId}`);
    return res.json({ success:true, newSeasonId: newId, newSeasonNumber: newNum,
      archived: { players: players.length, fixtures: fixtures.length, registrations: regs.length }
    });
  } catch(e) {
    console.error('[CEE] startNewSeason:', e);
    return res.status(500).json({ success:false, message: e.message });
  }
});

// POST /submitRegistration — public endpoint, saves pending reg after payment
// Player is NOT created here. Admin approves via /approveRegistration which
// creates the player doc, hashes the PIN, and emails credentials.
// ═══════════════════════════════════════════════════════════════════════════
app.post('/submitRegistration', async (req, res) => {
  const { seasonId, realName, gameName, clubName, initials,
          email, phone, strength, teamChoice, payRef, pot } = req.body;
  if (!seasonId || !gameName || !email || !payRef) {
    return res.status(400).json({ success:false, message:'Missing required fields' });
  }
  try {
    // 1. Verify season is accepting registrations
    const seasonDoc = await db.collection('seasons').doc(seasonId).get();
    if (!seasonDoc.exists) return res.json({ success:false, message:'Season not found.' });
    const season = seasonDoc.data();
    if (season.status !== 'registration_open') {
      return res.json({ success:false, message:'Registration is not currently open.' });
    }

    // 2. Prevent duplicate payment reference (replay protection)
    const dupRef = await db.collection('registrations')
      .where('seasonId','==',seasonId).where('payRef','==',payRef).limit(1).get();
    if (!dupRef.empty) {
      return res.json({ success:false, message:'This payment reference has already been used.' });
    }

    // 3. Prevent duplicate email in this season
    const dupEmail = await db.collection('registrations')
      .where('seasonId','==',seasonId).where('email','==',email.toLowerCase().trim()).limit(1).get();
    if (!dupEmail.empty) {
      return res.json({ success:false, message:'This email address is already registered for this season.' });
    }

    // 4. Prevent duplicate gaming tag in this season
    const dupTag = await db.collection('players')
      .where('seasonId','==',seasonId).where('gameName','==',gameName.trim()).limit(1).get();
    if (!dupTag.empty) {
      return res.json({ success:false, message:'This gaming tag is already in use this season.' });
    }

    // 5. Check slot availability (count approved players + pending regs together)
    const [existingPlayers, existingPending] = await Promise.all([
      db.collection('players').where('seasonId','==',seasonId).get(),
      db.collection('registrations').where('seasonId','==',seasonId)
        .where('status','in',['pending','approved']).get()
    ]);
    const slotsFilled = Math.max(existingPlayers.size, existingPending.size);
    if (slotsFilled >= (season.format || 20)) {
      return res.json({ success:false, message:'All registration slots are filled.' });
    }

    // 6. Save pending registration
    const regRef = await db.collection('registrations').add({
      seasonId,
      realName:   (realName || '').trim(),
      gameName:   gameName.trim(),
      clubName:   (clubName || '').trim(),
      initials:   (initials || gameName.substring(0,2)).toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,6),
      email:      email.toLowerCase().trim(),
      phone:      (phone || '').trim(),
      strength:   Number(strength) || 0,
      teamChoice: teamChoice || 'random',
      pot:        Number(pot) || null,
      payRef,
      status:     'pending',
      submittedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // 7. Notify admin
    const adminChat  = env.telegram && env.telegram.admin_chat_id;
    const adminEmail = env.admin    && env.admin.email;
    const tgMsg = `📋 <b>New Registration</b>\n👤 ${gameName} (${email})\n🏟️ ${clubName||'Random team'}\n💳 Ref: ${payRef}\n\nApprove in admin panel to issue their PIN.`;
    if (adminChat)  sendTelegram(adminChat, tgMsg).catch(()=>{});
    if (adminEmail) sendEmail(adminEmail, 'CEE — New Registration Pending Review',
      `<p>📋 A new registration is waiting for your review.</p>
       <div class="hl">
         <strong>Name:</strong> ${realName||gameName}<br>
         <strong>Email:</strong> ${email}<br>
         <strong>Gaming Tag:</strong> ${gameName}<br>
         <strong>Club:</strong> ${clubName||'Random assignment'}<br>
         <strong>Payment Ref:</strong> ${payRef}
       </div>
       <p>Log into the CEE admin panel → Registrations tab to approve or reject.</p>`
    ).catch(()=>{});

    await audit('REGISTRATION_SUBMITTED', regRef.id, 'registration', `${gameName} (${email}) submitted registration`);
    return res.json({ success:true, regId:regRef.id });
  } catch(e) {
    console.error('[CEE] submitRegistration:', e);
    return res.status(500).json({ success:false, message:'Server error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /bulkIssuePins — issue PINs to all players in a season who have no
// PIN hash yet in playerSecrets. Safe to call multiple times (idempotent).
// ═══════════════════════════════════════════════════════════════════════════
app.post('/bulkIssuePins', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { seasonId } = req.body;
  if (!seasonId) return res.status(400).json({ success:false, message:'Missing seasonId' });
  try {
    const players = await db.collection('players').where('seasonId','==',seasonId).get();
    let issued = 0, skipped = 0;
    for (const pd of players.docs) {
      const secretDoc = await db.collection('playerSecrets').doc(pd.id).get();
      const secrets   = secretDoc.exists ? secretDoc.data() : {};
      if (secrets.pinHash) { skipped++; continue; } // already has a PIN
      const player = pd.data();
      const pin    = String(Math.floor(1000 + Math.random() * 9000));
      const pinHash = await bcrypt.hash(pin, 12);
      await db.collection('playerSecrets').doc(pd.id).set(
        { pinHash, pinFailAttempts:0, pinLockoutUntil:null, pinLockoutCount:0 }, { merge:true }
      );
      if (player.email) {
        await sendEmail(player.email, 'CEE — Your Player PIN',
          `<p>Welcome to <strong>Campus eSports Elite</strong>!</p>
           <p>Your Player Hub PIN is:</p>
           <div class="hl" style="font-size:36px;font-weight:700;letter-spacing:.5em;text-align:center">${pin}</div>
           <p><strong>Keep this private.</strong> Use it to log into the CEE Player Hub.</p>`
        ).catch(()=>{});
      }
      await audit('PIN_BULK_ISSUED', pd.id, 'player', `Bulk PIN issued to ${player.email||player.gameName}`);
      issued++;
    }
    return res.json({ success:true, issued, skipped });
  } catch(e) { return res.status(500).json({ success:false, message:e.message }); }
});

// POST /suggestInitials — AI-powered initials suggestion
// ═══════════════════════════════════════════════════════════════════════════
app.post('/suggestInitials', async (req, res) => {
  // Public endpoint — no admin secret required (used during registration)
  const { gameName, clubName } = req.body;
  const name = gameName || clubName || '';
  if (!name) return res.status(400).json({ success: false, message: 'Missing name' });

  const words = name.trim().split(/\s+/);
  const suggestions = [];

  // Suggestion 1: first letters of each word (up to 6 chars)
  if (words.length >= 2) {
    suggestions.push(words.map(w => w[0]).join('').toUpperCase().slice(0, 6));
  }

  // Suggestion 2: first 3 letters of first word + first 3 of last word
  if (words.length >= 2) {
    const s2 = (words[0].slice(0, 3) + words[words.length - 1].slice(0, 3)).toUpperCase();
    if (s2 !== suggestions[0]) suggestions.push(s2);
  }

  // Suggestion 3: first 6 characters of the name (no spaces)
  const s3 = name.replace(/\s+/g, '').toUpperCase().slice(0, 6);
  if (!suggestions.includes(s3)) suggestions.push(s3);

  // Ensure at least one suggestion
  if (!suggestions.length) suggestions.push(name.substring(0, 2).toUpperCase());

  return res.json({ success: true, suggestions });
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /adminHubData?playerId=XXX — Admin test hub: load full hub state for
// any player without requiring their PIN. Admin secret required.
// ═══════════════════════════════════════════════════════════════════════════
app.get('/adminHubData', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  const playerId = req.query.playerId;
  if (!playerId) return res.status(400).json({ success: false, message: 'playerId required' });
  try {
    const playerSnap = await db.collection('players').doc(playerId).get();
    if (!playerSnap.exists) return res.status(404).json({ success: false, message: 'Player not found' });
    const player = { id: playerSnap.id, ...playerSnap.data() };
    const seasonId = player.seasonId || await getSeasonId();

    // Load fixtures for this player
    const [fixA, fixB] = await Promise.all([
      db.collection('fixtures').where('seasonId','==',seasonId).where('playerAId','==',playerId).get(),
      db.collection('fixtures').where('seasonId','==',seasonId).where('playerBId','==',playerId).get()
    ]);
    const fixtures = [];
    fixA.forEach(d => fixtures.push({ id: d.id, ...d.data() }));
    fixB.forEach(d => fixtures.push({ id: d.id, ...d.data() }));

    // Load all players for standings context
    const playersSnap = await db.collection('players').where('seasonId','==',seasonId).get();
    const allPlayers = [];
    playersSnap.forEach(d => allPlayers.push({ id: d.id, ...d.data() }));

    return res.json({ success: true, player, fixtures, allPlayers, adminTestMode: true });
  } catch(e) {
    console.error('[CEE] adminHubData:', e);
    return res.status(500).json({ success: false, message: e.message });
  }
});

// GET /adminListPlayers — returns all players for admin hub picker
app.get('/adminListPlayers', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  try {
    const seasonId = await getSeasonId();
    if (!seasonId) return res.json({ success: true, players: [] });
    const snap = await db.collection('players').where('seasonId','==',seasonId).get();
    const players = [];
    snap.forEach(d => {
      const p = d.data();
      players.push({ id: d.id, clubName: p.clubName, gameName: p.gameName, stats: p.stats });
    });
    players.sort((a,b) => (a.clubName||a.gameName||'').localeCompare(b.clubName||b.gameName||''));
    return res.json({ success: true, players });
  } catch(e) {
    return res.status(500).json({ success: false, message: e.message });
  }
});
app.post('/telegramWebhook', async (req, res) => {
  res.status(200).send('OK'); // always respond 200 immediately
  try {
    const body=req.body;
    const message=body.message||body.edited_message;
    if (!message) return;
    const chatId=message.chat&&message.chat.id;
    const text=(message.text||'').trim();
    const username=message.from&&(message.from.username||'');
    if (!chatId) return;

    if (text.startsWith('/start')) {
      const parts=text.split(' '), tag=parts[1]?parts[1].trim():'';
      if (!tag) { await sendTelegram(chatId,`👋 Welcome to <b>CEE Bot</b>!\n\nTo link your account, send:\n<code>/start YourGamingTag</code>`); return; }
      const seasonId=await getSeasonId();
      if (!seasonId) { await sendTelegram(chatId,`⚠️ No active season found. Try again later.`); return; }
      const tagUpper=tag.toUpperCase();
      let found=null;
      const byGN=await db.collection('players').where('seasonId','==',seasonId).where('gameName','==',tagUpper).limit(1).get();
      if (!byGN.empty){ const d=byGN.docs[0]; found={id:d.id,...d.data()}; }
      if (!found){ const byCN=await db.collection('players').where('seasonId','==',seasonId).where('clubName','==',tagUpper).limit(1).get();
        if(!byCN.empty){const d=byCN.docs[0];found={id:d.id,...d.data()};} }
      if (!found&&username){ const byTg=await db.collection('players').where('seasonId','==',seasonId)
        .where('telegramUsername','==',username.toLowerCase().replace('@','')).limit(1).get();
        if(!byTg.empty){const d=byTg.docs[0];found={id:d.id,...d.data()};} }
      // Also search by Firestore doc ID (players copy their Player ID from the hub)
      if (!found) {
        try {
          const byId = await db.collection('players').doc(tag).get();
          if (byId.exists && byId.data().seasonId === seasonId) { found = { id: byId.id, ...byId.data() }; }
        } catch(_) {}
      }
      if (!found) { await sendTelegram(chatId,`❌ <b>${tag}</b> not found.\n\nTry:\n• Your gaming tag (e.g. <code>VIPER</code>)\n• Your full Player ID from the hub\n\nContact admin if issue persists.`); return; }
      await db.collection('players').doc(found.id).update({ telegramChatId:chatId, telegramUsername:username, notificationsTelegram:true });

      // Fetch player stats for a personalised welcome
      const s = found.stats || {};
      const tier = found.playerTier
        ? (found.playerTier==='elite' ? '🔴 Elite' : found.playerTier==='mid' ? '🟡 Mid' : '⚪ Underdog')
        : null;
      const potLabel = found.pot ? `P${found.pot}` : null;
      const statsLine = s.mp > 0
        ? `\nSeason record: ${s.mp} played · ${s.w}W ${s.d}D ${s.l}L · ${s.pts} pts`
        : '\nSeason record: No matches played yet';
      const tierLine = tier ? `\nTier: ${tier}` : '';
      const potLine  = potLabel ? ` · ${potLabel}` : '';

      await sendTelegram(chatId,
        `✅ <b>You're linked! Welcome to CEE.</b>\n\n`
        + `🎮 <b>${found.clubName || found.gameName}</b>${potLine}${tierLine}`
        + statsLine
        + `\n\n🔔 You'll now receive instant alerts for:\n`
        + `  • Match window opening\n`
        + `  • Opponent ready check-in\n`
        + `  • Result approvals\n`
        + `  • League announcements\n\n`
        + `📋 <b>Your commands:</b>\n`
        + `/status — your current stats &amp; rank\n`
        + `/fixtures — your upcoming matches\n`
        + `/help — all commands`);

      // Notify admin that a player has linked
      const adminChat = env.telegram && env.telegram.admin_chat_id;
      if (adminChat) {
        await sendTelegram(adminChat,
          `📱 <b>Player linked Telegram</b>\n${found.clubName||found.gameName} (@${username||'no username'})${potLine}`
        ).catch(()=>{});
      }

      await audit('TELEGRAM_LINKED',found.id,'player',`ChatId ${chatId} linked via /start`);
    }
    else if (text==='/status') {
      const seasonId=await getSeasonId();
      if (!seasonId){ await sendTelegram(chatId,'⚠️ No active season.'); return; }
      const snap=await db.collection('players').where('seasonId','==',seasonId).where('telegramChatId','==',chatId).limit(1).get();
      if (snap.empty){ await sendTelegram(chatId,'❌ Account not linked. Send /start YourTag'); return; }
      const p=snap.docs[0].data(), s=p.stats||{};
      // Add returning player context
      const returningNote = p.returningPlayer
        ? `\n🔄 <i>Returning player — history tracked across seasons</i>\n`
        + (p.integrityScore != null && p.integrityScore < 100 ? `Integrity: ${p.integrityScore}/100` : '')
        : '';
      const tierStr = p.playerTier ? ` | Tier: ${p.playerTier==='elite'?'🔴 Elite':p.playerTier==='mid'?'🟡 Mid':'⚪ Underdog'}` : '';
      await sendTelegram(chatId,
        `📊 <b>${p.clubName||p.gameName}</b>\nRank: #${p.rank||'—'}${tierStr}\nPoints: ${s.pts||0}\nMP: ${s.mp||0} | W: ${s.w||0} D: ${s.d||0} L: ${s.l||0}\nGF: ${s.gf||0} GA: ${s.ga||0} GD: ${s.gd>=0?'+':''}${s.gd||0}${returningNote}`);
    }
    else if (text==='/fixtures') {
      const seasonId=await getSeasonId();
      if (!seasonId){ await sendTelegram(chatId,'⚠️ No active season.'); return; }
      const pSnap=await db.collection('players').where('seasonId','==',seasonId).where('telegramChatId','==',chatId).limit(1).get();
      if (pSnap.empty){ await sendTelegram(chatId,'❌ Account not linked. Send /start YourTag'); return; }
      const playerId=pSnap.docs[0].id;
      const fSnap=await db.collection('fixtures').where('seasonId','==',seasonId)
        .where('status','in',['scheduled','window_open','ready_pending','in_progress']).get();
      const mine=fSnap.docs.filter(d=>d.data().playerAId===playerId||d.data().playerBId===playerId).slice(0,3);
      if (mine.length===0){ await sendTelegram(chatId,'📅 No upcoming fixtures found.'); return; }
      let msg=`📅 <b>Your upcoming fixtures:</b>\n\n`;
      for (const d of mine){ const f=d.data(); const opp=f.playerAId===playerId?(f.playerBName||f.playerBId):(f.playerAName||f.playerAId); msg+=`vs <b>${opp}</b>\nStatus: ${f.status}\n\n`; }
      await sendTelegram(chatId,msg);
    }
    else if (text==='/help') {
      await sendTelegram(chatId,
        `⚡ <b>CEE Bot Commands</b>\n\n`
        + `/status — your stats, rank &amp; tier\n`
        + `/fixtures — your upcoming matches\n`
        + `/help — show this list\n\n`
        + `To link your account, send:\n`
        + `<code>/start YourGamingTag</code>\n`
        + `or\n`
        + `<code>/start YourPlayerID</code> (from the hub)\n\n`
        + `Visit the CEE Player Hub for match details, fixtures and scores.`);
    }
  } catch(e){ console.error('[CEE] telegramWebhook:',e.message); }
});

// ═══════════════════════════════════════════════════════════════════════════
// ── SCHEDULED JOBS (node-cron replaces Firebase pubsub.schedule) ──────────
// All times are WAT (Africa/Lagos = UTC+1). node-cron runs in server local
// time, so we use UTC patterns and subtract 1 hour where needed.
// ═══════════════════════════════════════════════════════════════════════════

// ── windowManager — every 15 min ─────────────────────────────────────────
async function runWindowManager() {
  const seasonId = await getSeasonId(); if (!seasonId) return;
  const seasonDoc = await db.collection('seasons').doc(seasonId).get();
  if (!seasonDoc.exists || seasonDoc.data().forceMajeure) {
    console.log('[CEE] Force Majeure active — skipping window management'); return;
  }
  const nowTs  = nowTS();
  const nowDt  = nowWAT();
  const batch  = db.batch();
  const notifications = [];

  // ── 1. Open scheduled windows ──────────────────────────────────────────
  const toOpen = await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','==','scheduled').where('windowOpenTime','<=',nowTs).get();
  toOpen.forEach(doc => {
    const f = doc.data();
    if (f.windowCloseTime && nowTs.toMillis() > f.windowCloseTime.toMillis()) return;
    batch.update(doc.ref, { status: 'awaiting_proposal' });
    notifications.push({ type:'WINDOW_OPEN', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
  });

  // ── 2. Monitor open fixtures — reminders & check-in transitions ────────
  const openFix = await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','in',['awaiting_proposal','proposal_pending','time_agreed','checkin_open']).get();

  openFix.forEach(doc => {
    const f = doc.data();
    if (!f.windowOpenTime) return;
    const openedAt   = fromTS(f.windowOpenTime);
    const winClose   = f.windowCloseTime ? fromTS(f.windowCloseTime) : openedAt.plus({hours:9});
    const totalMins  = winClose.diff(openedAt,'minutes').minutes;
    const elapsedMins = nowDt.diff(openedAt,'minutes').minutes;
    const minsToClose = winClose.diff(nowDt,'minutes').minutes;

    // No proposal after 60% of window → remind both players
    const at60pct = totalMins * 0.6;
    if (['awaiting_proposal','window_open'].includes(f.status) &&
        elapsedMins >= at60pct && !f.noProposalReminderSent) {
      batch.update(doc.ref, { noProposalReminderSent: true });
      notifications.push({ type:'READY_REMINDER_1', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
    }

    // Proposal sent but no response for 90+ mins → nudge opponent
    if (f.status === 'proposal_pending' && f.lastProposalAt && !f.proposalNudgeSent) {
      const proposalAge = nowDt.diff(fromTS(f.lastProposalAt),'minutes').minutes;
      if (proposalAge >= 90) {
        batch.update(doc.ref, { proposalNudgeSent: true });
        notifications.push({ type:'READY_REMINDER_2', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
      }
    }

    // 1-hour warning before window closes (no agreement yet)
    if (['awaiting_proposal','proposal_pending'].includes(f.status) &&
        minsToClose >= 55 && minsToClose < 70 && !f.warn1hSent) {
      batch.update(doc.ref, { warn1hSent: true });
      notifications.push({ type:'DEADLINE_REMINDER', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
    }

    // time_agreed → send 1h and 15m reminders
    if (f.status === 'time_agreed' && f.agreedSlot) {
      const minsToMatch = fromTS(f.agreedSlot).diff(nowDt,'minutes').minutes;
      if (minsToMatch >= 55 && minsToMatch < 70 && !f.reminder1hSent) {
        batch.update(doc.ref, { reminder1hSent: true });
        notifications.push({ type:'CHECKIN_REMINDER_1H', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId, agreedSlot:f.agreedSlot });
      }
      if (minsToMatch >= 10 && minsToMatch < 20 && !f.reminder15mSent) {
        batch.update(doc.ref, { reminder15mSent: true });
        notifications.push({ type:'CHECKIN_REMINDER_15M', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId, agreedSlot:f.agreedSlot });
      }
      // Open check-in window when agreed time arrives
      if (minsToMatch <= 0 && !f.checkInWindowOpened) {
        batch.update(doc.ref, { status:'checkin_open', checkInWindowOpened:true });
        notifications.push({ type:'CHECKIN_OPEN', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
      }
    }

    // Proposal round 2 exhausted AND no response for 3h → auto-escalate to admin
    if (f.status === 'proposal_pending' && (f.proposalRound||0) >= 2 && f.lastProposalAt) {
      const age = nowDt.diff(fromTS(f.lastProposalAt),'hours').hours;
      if (age >= 3 && !f.adminArbitrationTriggered) {
        batch.update(doc.ref, { status:'admin_arbitration', adminArbitrationTriggered:true });
        notifications.push({ type:'ADMIN_ARBITRATION', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
      }
    }
  });

  // ── 3. Close expired windows ───────────────────────────────────────────
  const toClose = await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','in',['awaiting_proposal','proposal_pending','time_agreed','checkin_open','window_open','ready_pending','in_progress'])
    .where('windowCloseTime','<=',nowTs).get();

  const seenAutoApprove = [];
  toClose.forEach(doc => {
    const f = doc.data();
    const base = { adminApproved:true, autoApprovedAt:admin.firestore.FieldValue.serverTimestamp() };
    let result = null;

    // New statuses — no agreement or no check-in
    if (f.status === 'awaiting_proposal' || f.status === 'proposal_pending') {
      // Nobody agreed → void, no forfeit
      result = 'DNP';
      batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:0, playerBGoals:0, done:true, isForfeit:false });
    }
    else if (f.status === 'time_agreed') {
      // Agreed but check-in never opened (window closed before agreed time?) → void
      result = 'DNP';
      batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:0, playerBGoals:0, done:true, isForfeit:false });
    }
    else if (f.status === 'checkin_open') {
      const aIn = !!f.playerACheckedIn, bIn = !!f.playerBCheckedIn;
      if (!aIn && !bIn) {
        // Neither showed up → void
        result = 'DNP';
        batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:0, playerBGoals:0, done:true, isForfeit:false });
      } else if (aIn && !bIn) {
        // A showed, B didn't → forfeit B (they agreed and didn't show)
        result = 'FORFEIT_B';
        batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:3, playerBGoals:0, done:true, isForfeit:true });
        notifications.push({ type:'FORFEIT_APPLIED', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
      } else if (!aIn && bIn) {
        result = 'FORFEIT_A';
        batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:0, playerBGoals:3, done:true, isForfeit:true });
        notifications.push({ type:'FORFEIT_APPLIED', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
      }
    }
    // Legacy statuses — keep old behaviour
    else if (!f.playerAReadyAt && !f.playerBReadyAt) {
      result = 'DNP';
      batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:0, playerBGoals:0, done:true, isForfeit:false });
    }
    else if (f.playerAReadyAt && !f.playerBReadyAt) {
      result = 'FORFEIT_B';
      batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:3, playerBGoals:0, done:true, isForfeit:true });
      notifications.push({ type:'FORFEIT_APPLIED', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
    }
    else if (!f.playerAReadyAt && f.playerBReadyAt) {
      result = 'FORFEIT_A';
      batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:0, playerBGoals:3, done:true, isForfeit:true });
      notifications.push({ type:'FORFEIT_APPLIED', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
    }
    else if (f.bothReadyAt && !f.playerASubmittedAt && !f.playerBSubmittedAt) {
      result = 'DNP';
      batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:0, playerBGoals:0, done:true, isForfeit:false });
    }
    else if (f.playerASubmittedAt && !f.playerBSubmittedAt) {
      result = 'FORFEIT_B';
      batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:3, playerBGoals:0, done:true, isForfeit:true });
      notifications.push({ type:'FORFEIT_APPLIED', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
    }
    else if (!f.playerASubmittedAt && f.playerBSubmittedAt) {
      result = 'FORFEIT_A';
      batch.update(doc.ref, { ...base, status:'approved', result, playerAGoals:0, playerBGoals:3, done:true, isForfeit:true });
      notifications.push({ type:'FORFEIT_APPLIED', fixtureId:doc.id, pA:f.playerAId, pB:f.playerBId });
    }

    if (result) {
      seenAutoApprove.push(doc.id);
      audit('WINDOW_CLOSED_AUTO', doc.id, 'fixture', `Result: ${result}`).catch(()=>{});
    }
  });

  await batch.commit();

  // Send notifications — pass agreedSlot extra data where needed
  for (const n of notifications) {
    if (n.type === 'CHECKIN_REMINDER_1H' || n.type === 'CHECKIN_REMINDER_15M') {
      await _notifyProposal(n.type, n.pA, n.fixtureId, { agreedSlot: n.agreedSlot });
      await _notifyProposal(n.type, n.pB, n.fixtureId, { agreedSlot: n.agreedSlot });
    } else if (n.type === 'CHECKIN_OPEN') {
      await _notifyProposal(n.type, n.pA, n.fixtureId, {});
      await _notifyProposal(n.type, n.pB, n.fixtureId, {});
    } else if (n.type === 'ADMIN_ARBITRATION') {
      await _notifyProposal(n.type, n.pA, n.fixtureId, {});
    } else {
      await _sendMatchNotifications(n.type, n.fixtureId, n.pA, n.pB, seasonId);
    }
  }

  if (seenAutoApprove.length > 0) {
    await db.collection('seasons').doc(seasonId).update({ standingsDirty:true }).catch(()=>{});
    await _recalcStandingsInternal(seasonId);
    await _checkKnockoutQualification(seasonId);
  }
  console.log(`[CEE] windowManager: opened=${toOpen.size}, closed=${seenAutoApprove.length}`);
}
cron.schedule('*/15 * * * *', () => runWindowManager().catch(e => console.error('[CEE] windowManager error:',e)));

// ── submissionDeadlineEnforcer — every 10 min ─────────────────────────────
async function runSubmissionDeadlineEnforcer() {
  const seasonId=await getSeasonId(); if (!seasonId) return;
  const nowTs=nowTS();
  const snap=await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','==','in_progress').where('submissionDeadline','<=',nowTs).get();
  const batch=db.batch(); const notifys=[];
  for (const doc of snap.docs) {
    const f=doc.data(); let result,hg,ag,isForfeit;
    if (!f.playerASubmittedAt&&!f.playerBSubmittedAt){ result='DNP';hg=0;ag=0;isForfeit=false; }
    else if (f.playerASubmittedAt&&!f.playerBSubmittedAt){ result='FORFEIT_B';hg=3;ag=0;isForfeit=true; notifys.push({type:'FORFEIT_APPLIED',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId}); }
    else if (!f.playerASubmittedAt&&f.playerBSubmittedAt){ result='FORFEIT_A';hg=0;ag=3;isForfeit=true; notifys.push({type:'FORFEIT_APPLIED',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId}); }
    else continue;
    batch.update(doc.ref,{status:'approved',result,isForfeit,playerAGoals:hg,playerBGoals:ag,adminApproved:true,done:true,autoApprovedAt:admin.firestore.FieldValue.serverTimestamp()});
    audit('DEADLINE_FORFEIT',doc.id,'fixture',`Deadline passed. Result: ${result}`).catch(()=>{});
  }
  await batch.commit();
  for (const n of notifys) await _sendMatchNotifications(n.type,n.fixtureId,n.pA,n.pB,seasonId);
  if (snap.size>0) {
    await db.collection('seasons').doc(seasonId).update({standingsDirty:true}).catch(()=>{});
    await _recalcStandingsInternal(seasonId); await _checkKnockoutQualification(seasonId);
  }
  console.log(`[CEE] submissionDeadlineEnforcer: processed ${snap.size}`);
}
cron.schedule('*/10 * * * *', () => runSubmissionDeadlineEnforcer().catch(e => console.error('[CEE] submissionDeadlineEnforcer error:',e)));


// ── Auto-approve registrations after 48hr (if toggle enabled) ────────────
setInterval(async () => {
  try {
    const cfg = await db.collection('config').doc('automation').get();
    const d = cfg.exists ? cfg.data() : {};
    if (!d.masterEnabled && d.masterEnabled !== undefined) return;
    if (!d.autoApproveReg && d.autoApproveReg !== undefined) return;
    const cutoff = admin.firestore.Timestamp.fromMillis(Date.now() - 48*60*60*1000);
    const pending = await db.collection('registrations')
      .where('status','==','pending')
      .where('submittedAt','<=',cutoff)
      .get();
    for (const doc of pending.docs) {
      const reg = doc.data();
      try {
        // Auto-approve: generate PIN + create player (reuse approveRegistration logic)
        const playerPin = String(Math.floor(1000+Math.random()*9000));
        const pinHash = await bcrypt.hash(playerPin, 12);
        const seasonId = reg.seasonId;
        const regStrength = Number(reg.strength) || 0;
        const cfgDoc = await db.collection('config').doc('automation').get();
        const thresh = (cfgDoc.exists && cfgDoc.data().potThresholds) || { p1:3250, p2:3150, p3:3000 };
        const autoPot = reg.pot ? Number(reg.pot) :
          regStrength >= thresh.p1 ? 1 : regStrength >= thresh.p2 ? 2 : regStrength >= thresh.p3 ? 3 : 4;
        const playerRef = await db.collection('players').add({
          seasonId, gameName:reg.gameName||'', clubName:reg.clubName||'',
          initials:reg.initials||(reg.gameName||'').substring(0,2).toUpperCase(),
          email:reg.email||'', phone:reg.phone?String(reg.phone).replace(/\D/g,''):null,
          telegramChatId:null, notificationsEmail:true, notificationsTelegram:true,
          registrationId:doc.id, legacyId:null, fromReg:true,
          strength:regStrength, pot:autoPot,
          stats:{pts:0,mp:0,pld:0,w:0,d:0,l:0,gf:0,ga:0,gd:0,goals:0},
          rank:null, knockoutStatus:null, integrityScore:100,
          createdAt:admin.firestore.FieldValue.serverTimestamp()
        });
        await db.collection('playerSecrets').doc(playerRef.id).set(
          {pinHash,pinFailAttempts:0,pinLockoutUntil:null,pinLockoutCount:0});
        await doc.ref.update({status:'approved',playerId:playerRef.id,
          approvedAt:admin.firestore.FieldValue.serverTimestamp(),autoApproved:true});
        if (reg.email) {
          sendEmail(reg.email,'CEE — Registration Approved (Auto) 🎮',
            `<p>Your registration has been automatically approved after 48 hours.</p>
             <div class="hl" style="font-size:24px;font-weight:700;letter-spacing:.3em">PIN: ${playerPin}</div>
             <p>Keep this PIN private. Use it to access the CEE Player Hub.</p>`).catch(()=>{});
        }
        console.log(`[CEE] Auto-approved registration ${doc.id} for ${reg.gameName}`);
      } catch(e) { console.error('[CEE] Auto-approve reg error:', doc.id, e.message); }
    }
  } catch(e) { console.error('[CEE] Auto-approve cron error:', e.message); }
}, 15 * 60 * 1000); // every 15 minutes

// ── Auto-launch tournament when deadline passed + slots full ─────────────
setInterval(async () => {
  try {
    const cfg = await db.collection('config').doc('automation').get();
    const d = cfg.exists ? cfg.data() : {};
    if (!d.masterEnabled && d.masterEnabled !== undefined) return;
    if (!d.autoLaunch && d.autoLaunch !== undefined) return;
    // Get active season
    const seasonCfg = await db.collection('config').doc('season').get();
    if (!seasonCfg.exists) return;
    const seasonId = seasonCfg.data().activeSeasonId;
    if (!seasonId) return;
    const seasonDoc = await db.collection('seasons').doc(seasonId).get();
    if (!seasonDoc.exists) return;
    const season = seasonDoc.data();
    // Only run if season is registration_open
    if (season.status !== 'registration_open') return;
    // Check deadline
    const now = Date.now();
    const deadline = season.registrationDeadline ? season.registrationDeadline.toMillis() : null;
    const deadlinePassed = deadline && now > deadline;
    // Check slots
    const playersSnap = await db.collection('players').where('seasonId','==',seasonId).get();
    const format = season.format || 20;
    const slotsFull = playersSnap.size >= format;
    if (!deadlinePassed && !slotsFull) return;
    // Mark season as active
    await db.collection('seasons').doc(seasonId).update({
      status:'active', autoLaunchedAt:admin.firestore.FieldValue.serverTimestamp()
    });
    // Notify all players
    if (d.autoSeasonNotify !== false) {
      const allPlayers = await db.collection('players').where('seasonId','==',seasonId).get();
      const tgMsg = `🏆 <b>CEE Season is LIVE!</b>

The tournament has officially started!

Log in to the Player Hub to view your fixtures and get ready for your first match.

⚡ ${process.env.SITE_URL||'https://cee-esports.web.app'}`;
      for (const p of allPlayers.docs) {
        const pd = p.data();
        if (pd.telegramChatId) sendTelegram(pd.telegramChatId, tgMsg).catch(()=>{});
        if (pd.pushSubscription) {
          let sub; try { sub = typeof pd.pushSubscription==='string' ? JSON.parse(pd.pushSubscription) : pd.pushSubscription; } catch(e){sub=null;}
          if (sub) _sendWebPush(sub, { title:'🏆 CEE Season is LIVE!', body:'The tournament has started! Check your fixtures now.', eventType:'SEASON_LAUNCHED', data:{url:`${process.env.SITE_URL||'https://cee-esports.web.app'}#fixtures`} }).catch(()=>{});
        }
      }
    }
    const adminChat = env.telegram && env.telegram.admin_chat_id;
    if (adminChat) sendTelegram(adminChat,
      `🚀 <b>Season Auto-Launched!</b>
Season: ${seasonId}
Players: ${playersSnap.size}/${format}
Reason: ${slotsFull ? 'Slots full' : 'Deadline passed'}`
    ).catch(()=>{});
    console.log(`[CEE] Auto-launch triggered for ${seasonId}`);
  } catch(e) { console.error('[CEE] Auto-launch cron error:', e.message); }
}, 10 * 60 * 1000); // every 10 minutes

// ── autoApprover — every 5 min — GUARD-01, Auto-16 (48hr flagged) ─────────
async function runAutoApprover() {
  const seasonId=await getSeasonId(); if (!seasonId) return;
  const nowTs=nowTS();
  const adminEmail=env.admin&&env.admin.email;
  const adminChat=env.telegram&&env.telegram.admin_chat_id;

  const pending=await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','==','pending_approval').where('adminApproved','==',false)
    .where('autoApproveAt','<=',nowTs).get();
  const batch=db.batch(); const notifys=[];

  pending.forEach(doc => {
    const f=doc.data();
    if (f.screenshotFlaggedForReview) return; // handled by 48hr path below
    batch.update(doc.ref,{adminApproved:true,status:'approved',done:true,autoApprovedAt:admin.firestore.FieldValue.serverTimestamp()});
    notifys.push({type:'RESULT_APPROVED',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId});
    audit('AUTO_APPROVED_45MIN',doc.id,'fixture','45-minute auto-approve triggered').catch(()=>{});
  });

  // 6hr and 1hr admin warnings
  const warningSoon=await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','==','pending_approval').where('adminApproved','==',false).get();
  for (const doc of warningSoon.docs) {
    const f=doc.data(); if (!f.autoApproveAt) continue;
    const minutesLeft=fromTS(f.autoApproveAt).diff(nowWAT(),'minutes').minutes;
    if (minutesLeft>0&&minutesLeft<=60&&!f.warn1hSent) {
      batch.update(doc.ref,{warn1hSent:true});
      if (adminChat) await sendTelegram(adminChat,`⏰ <b>Auto-approve in ~1 hour</b>\nFixture ${doc.id} will auto-approve if no admin action.`);
    }
    if (minutesLeft>300&&minutesLeft<=360&&!f.warn6hSent) {
      batch.update(doc.ref,{warn6hSent:true});
      if (adminChat) await sendTelegram(adminChat,`⏰ <b>Auto-approve in ~6 hours</b>\nFixture ${doc.id} will auto-approve if no admin action.`);
    }
  }

  // 48hr flagged screenshot auto-accept — Auto-16
  const flagged48=await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','==','pending_approval').where('screenshotFlaggedForReview','==',true).get();
  for (const doc of flagged48.docs) {
    const f=doc.data(); if (!f.playerASubmittedAt) continue;
    const hoursElapsed=nowWAT().diff(fromTS(f.playerASubmittedAt),'hours').hours;
    if (hoursElapsed>=48) {
      batch.update(doc.ref,{adminApproved:true,status:'approved',done:true,
        autoApprovedAt:admin.firestore.FieldValue.serverTimestamp(),
        autoApproveReason:'Flagged screenshot auto-accepted after 48hr admin absence'});
      notifys.push({type:'RESULT_APPROVED',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId});
      audit('AUTO_APPROVED_48HR_FLAG',doc.id,'fixture','48hr flagged screenshot auto-accept').catch(()=>{});
      if (adminEmail) sendEmail(adminEmail,'CEE — Auto-Accepted Flagged Screenshot',
        `<p>⚠️ Fixture <strong>${doc.id}</strong> was auto-approved after 48 hours because the flagged screenshot was not reviewed.</p>`
      ).catch(()=>{});
    }
  }

  await batch.commit();
  for (const n of notifys) await _sendMatchNotifications(n.type,n.fixtureId,n.pA,n.pB,seasonId);
  if (notifys.length>0) {
    await db.collection('seasons').doc(seasonId).update({standingsDirty:true}).catch(()=>{});
    await _recalcStandingsInternal(seasonId); await _checkKnockoutQualification(seasonId);
  }
  console.log(`[CEE] autoApprover: ${pending.size} 45min + ${flagged48.size} flagged`);
}
cron.schedule('*/5 * * * *', () => runAutoApprover().catch(e => console.error('[CEE] autoApprover error:',e)));

// ── disputeAutoResolver — every 30 min — NOTIF-01 ────────────────────────
async function runDisputeAutoResolver() {
  const adminEmail=env.admin&&env.admin.email;
  const adminChat=env.telegram&&env.telegram.admin_chat_id;
  const disputes=await db.collection('disputes').where('status','==','open').get();
  const batch=db.batch(); const notifys=[];
  for (const doc of disputes.docs) {
    const d=doc.data(); if (!d.openedAt) continue;
    const hoursOpen=nowWAT().diff(fromTS(d.openedAt),'hours').hours;
    if (hoursOpen>=66&&hoursOpen<66.5&&!d.warn6hSent) {
      batch.update(doc.ref,{warn6hSent:true});
      if (adminChat) await sendTelegram(adminChat,`⚖️ <b>Dispute auto-resolves in ~6 hours</b>\nDispute for fixture ${d.fixtureId} — please review.`);
      if (adminEmail) sendEmail(adminEmail,'CEE — Dispute Resolving in 6 Hours',
        `<p>⚖️ Dispute for fixture <strong>${d.fixtureId}</strong> will auto-resolve as 0–0 in approximately 6 hours if no admin action is taken.</p>`).catch(()=>{});
    }
    if (hoursOpen>=71&&hoursOpen<71.5&&!d.warn1hSent) {
      batch.update(doc.ref,{warn1hSent:true});
      if (adminChat) await sendTelegram(adminChat,`⚖️ <b>Dispute auto-resolves in ~1 hour</b>\nFixture: ${d.fixtureId}`);
    }
    if (hoursOpen>=72) {
      batch.update(doc.ref,{status:'auto_resolved',verdict:'0-0',resolvedAt:admin.firestore.FieldValue.serverTimestamp(),resolvedBy:'system'});
      batch.update(db.collection('fixtures').doc(d.fixtureId),{
        status:'approved',adminApproved:true,done:true,
        playerAGoals:0,playerBGoals:0,result:'DISPUTE_AUTO_RESOLVED',
        autoApprovedAt:admin.firestore.FieldValue.serverTimestamp()
      });
      notifys.push({type:'DISPUTE_AUTO_RESOLVED',fixtureId:d.fixtureId,pA:d.playerAId,pB:d.playerBId});
      audit('DISPUTE_AUTO_RESOLVED',d.fixtureId,'fixture','72hr auto-resolve: 0-0 draw').catch(()=>{});
    }
  }
  await batch.commit();
  for (const n of notifys) await _sendMatchNotifications('DISPUTE_AUTO_RESOLVED',n.fixtureId,n.pA,n.pB,null);
  if (notifys.length>0) {
    const seasonId=await getSeasonId();
    if (seasonId) {
      await db.collection('seasons').doc(seasonId).update({standingsDirty:true}).catch(()=>{});
      await _recalcStandingsInternal(seasonId);
    }
  }
  console.log(`[CEE] disputeAutoResolver: processed ${disputes.size} disputes`);
}
cron.schedule('*/30 * * * *', () => runDisputeAutoResolver().catch(e => console.error('[CEE] disputeAutoResolver error:',e)));

// ── doubleConsentExpiryEnforcer — every 30 min ────────────────────────────
async function runDoubleConsentExpiryEnforcer() {
  const snap=await db.collection('fixtures').where('doubleConsentRequestedAt','!=',null).get();
  const batch=db.batch(); let count=0;
  for (const doc of snap.docs) {
    const f=doc.data();
    if (!f.doubleConsentExpiresAt) continue;
    if (f.doubleConsentA&&f.doubleConsentB) continue;
    if (nowWAT()<fromTS(f.doubleConsentExpiresAt)) continue;
    batch.update(doc.ref,{doubleConsentExpired:true,doubleConsentRequestedAt:null});
    count++;
    for (const pid of [f.playerAId,f.playerBId]) {
      if (!pid) continue;
      const pd=await db.collection('players').doc(pid).get();
      if (!pd.exists) continue;
      const p=pd.data();
      const msg=`⏰ Double fixture consent request for fixture ${doc.id} has expired without both players agreeing.`;
      if (p.telegramChatId&&p.notificationsTelegram!==false) sendTelegram(p.telegramChatId,msg).catch(()=>{});
      if (p.email&&p.notificationsEmail!==false) sendEmail(p.email,'CEE — Double Fixture Consent Expired',`<p>${msg}</p>`).catch(()=>{});
    }
  }
  await batch.commit();
  console.log(`[CEE] doubleConsentExpiryEnforcer: expired ${count} requests`);
}
cron.schedule('*/30 * * * *', () => runDoubleConsentExpiryEnforcer().catch(e => console.error('[CEE] doubleConsentExpiryEnforcer error:',e)));

// ── swissPairingEngine — every 6 hours — RES-3: transaction prevents duplicates
async function runSwissPairingEngine() {
  const seasonId=await getSeasonId(); if (!seasonId) return;
  const seasonDoc=await db.collection('seasons').doc(seasonId).get();
  if (!seasonDoc.exists) return;
  const season=seasonDoc.data();
  if (season.status!=='active'||season.leagueFrozen) return;
  const fixtures=await getFixtures(seasonId);
  const leagueFix=fixtures.filter(f=>f.phase==='league'||!f.phase);
  const byWeek={};
  leagueFix.forEach(f=>{ const w=f.week||1; if(!byWeek[w])byWeek[w]=[]; byWeek[w].push(f); });
  const weeks=Object.keys(byWeek).map(Number).sort();
  const lastCompleteWeek=weeks.filter(w=>byWeek[w].every(f=>f.done)).pop()||0;
  const lastScheduledWeek=Math.max(...weeks,0);
  const players=await getPlayers(seasonId);
  const totalWeeks=Math.ceil(players.length-1);

  if (lastScheduledWeek===0&&season.registrationDeadline) {
    const deadlinePassed=nowWAT().diff(fromTS(season.registrationDeadline),'hours').hours;
    if (deadlinePassed>=48&&!season.week1AutoGenerated) {
      await _generateWeekFixtures(seasonId,1,players,[],season);
      await seasonDoc.ref.update({week1AutoGenerated:true});
      const adminChat=env.telegram&&env.telegram.admin_chat_id;
      if (adminChat) await sendTelegram(adminChat,'⚙️ <b>Week 1 auto-generated</b> (48hr admin fallback)');
      console.log('[CEE] Week 1 auto-generated (48hr fallback)');
    }
    return;
  }

  const nextWeek=lastCompleteWeek+1;
  if (nextWeek>totalWeeks) return;
  if (byWeek[nextWeek]&&byWeek[nextWeek].length>0) return;

  const standings=await _recalcStandingsInternal(seasonId);
  const pairs=swissPair(standings,leagueFix);
  if (pairs.length===0){ console.log('[CEE] No valid pairs found (all matchups exhausted)'); return; }

  const weekFlagKey=`week${nextWeek}Generated`;
  try {
    await db.runTransaction(async t => {
      const sDoc=await t.get(seasonDoc.ref);
      if (sDoc.data()[weekFlagKey]) throw new Error(`week${nextWeek} already generated`);
      t.update(seasonDoc.ref,{[weekFlagKey]:true});
    });
  } catch(txErr){ console.log(`[CEE] swissPairingEngine: ${txErr.message} — skipping`); return; }

  await _generateWeekFixtures(seasonId,nextWeek,players,pairs,season);
  console.log(`[CEE] Swiss pairs generated for Week ${nextWeek}: ${pairs.length} fixtures`);
}
cron.schedule('0 */6 * * *', () => runSwissPairingEngine().catch(e => console.error('[CEE] swissPairingEngine error:',e)));

// ── registrationDeadlineChecker — daily at midnight UTC (01:00 WAT) ───────
async function runRegistrationDeadlineChecker() {
  const seasonId=await getSeasonId(); if (!seasonId) return;
  const seasonDoc=await db.collection('seasons').doc(seasonId).get();
  if (!seasonDoc.exists) return;
  const season=seasonDoc.data();
  if (!season.registrationDeadline||season.registrationExtended) return;
  if (season.status!=='registration') return;
  if (nowWAT()<=fromTS(season.registrationDeadline)) return;
  const regs=await db.collection('registrations').where('seasonId','==',seasonId).where('approved','==',true).get();
  const targetSize=season.format||20;
  if (regs.size>=targetSize) return;
  const newDeadline=fromTS(season.registrationDeadline).plus({hours:48});
  await seasonDoc.ref.update({ registrationDeadline:toTS(newDeadline), registrationExtended:true });
  const adminEmail=env.admin&&env.admin.email, adminChat=env.telegram&&env.telegram.admin_chat_id;
  const msg=`📋 Registration deadline auto-extended 48 hours (${regs.size}/${targetSize} spots filled).`;
  if (adminChat) await sendTelegram(adminChat,`📋 <b>Registration deadline extended</b>\n${regs.size}/${targetSize} players registered. Deadline extended by 48 hours.`);
  if (adminEmail) await sendEmail(adminEmail,'CEE — Registration Deadline Extended',`<p>${msg}</p>`);
  const players=await getPlayers(seasonId);
  await Promise.allSettled(players.map(p => p.telegramChatId
    ? sendTelegram(p.telegramChatId,`📋 CEE registration deadline extended by 48 hours (${regs.size}/${targetSize}). Spread the word!`).catch(()=>{})
    : Promise.resolve()
  ));
  await audit('REGISTRATION_DEADLINE_EXTENDED',seasonId,'season',`Extended 48hr. ${regs.size}/${targetSize} registered.`);
  console.log('[CEE] Registration deadline extended 48hr');
}
cron.schedule('0 0 * * *', () => runRegistrationDeadlineChecker().catch(e => console.error('[CEE] registrationDeadlineChecker error:',e)));

// ── dailyAdminDigest — 08:00 WAT = 07:00 UTC ─────────────────────────────
async function runDailyAdminDigest() {
  const seasonId=await getSeasonId();
  const adminEmail=env.admin&&env.admin.email, adminChat=env.telegram&&env.telegram.admin_chat_id;
  if (!adminEmail&&!adminChat) return;
  const yesterday=nowWAT().minus({hours:24}), yesterdayTs=toTS(yesterday);
  let approved=[],openDisputes=[],flagged=[],failedNotifs=[],upcomingDeadlines=[];
  if (seasonId) {
    const [autoSnap,resolvedSnap]=await Promise.all([
      db.collection('fixtures').where('seasonId','==',seasonId).where('autoApprovedAt','>=',yesterdayTs).get(),
      db.collection('fixtures').where('seasonId','==',seasonId).where('disputeResolvedAt','>=',yesterdayTs).get()
    ]);
    const approvedIdSet=new Set([...autoSnap.docs,...resolvedSnap.docs].map(d=>d.id));
    approvedIdSet.forEach(id=>{
      const doc=autoSnap.docs.find(d=>d.id===id)||resolvedSnap.docs.find(d=>d.id===id);
      if (doc) approved.push(doc.data());
    });
    const disSnap=await db.collection('disputes').where('status','==','open').get();
    disSnap.forEach(d=>{ const data=d.data(); openDisputes.push({id:d.id,...data,hoursOpen:Math.round(nowWAT().diff(fromTS(data.openedAt),'hours').hours)}); });
    const flagSnap=await db.collection('fixtures').where('seasonId','==',seasonId)
      .where('screenshotFlaggedForReview','==',true).where('adminApproved','==',false).get();
    flagSnap.forEach(d=>flagged.push(d.id));
    const nextDay=toTS(nowWAT().plus({hours:24}));
    const deadSnap=await db.collection('fixtures').where('seasonId','==',seasonId)
      .where('status','==','in_progress').where('submissionDeadline','<=',nextDay).get();
    deadSnap.forEach(d=>upcomingDeadlines.push(d.id));
  }
  const notifSnap=await db.collection('notifications').where('status','==','failed').where('sentAt','>=',yesterdayTs).get();
  notifSnap.forEach(d=>failedNotifs.push(d.data()));
  const htmlBody=`
    <p><strong>📊 Daily League Digest — ${nowWAT().toFormat('dd MMM yyyy, HH:mm')} WAT</strong></p>
    <div class="hl">
      ✅ Results approved (last 24hr): <strong>${approved.length}</strong><br>
      ⚖️ Open disputes: <strong>${openDisputes.length}</strong><br>
      🚩 Flagged screenshots pending: <strong>${flagged.length}</strong><br>
      ❌ Failed notifications (last 24hr): <strong>${failedNotifs.length}</strong><br>
      ⏰ Submission deadlines in next 24hr: <strong>${upcomingDeadlines.length}</strong>
    </div>
    ${openDisputes.length>0?`<p><strong>Open Disputes:</strong></p><ul>${openDisputes.map(d=>`<li>Fixture ${d.fixtureId} — ${d.hoursOpen}hrs open (auto-resolves at 72hr)</li>`).join('')}</ul>`:''}
    ${flagged.length>0?`<p><strong>Flagged Screenshots:</strong> ${flagged.join(', ')}</p>`:''}
    ${failedNotifs.length>0?`<p><strong>Failed Notifications:</strong> ${failedNotifs.length} — retry from admin panel.</p>`:''}
    <p>Review all pending items in the admin panel.</p>`;
  if (adminEmail) await sendEmail(adminEmail,`CEE Daily Digest — ${nowWAT().toFormat('dd MMM yyyy')}`,htmlBody);
  if (adminChat) await sendTelegram(adminChat,`📊 <b>CEE Daily Digest</b>\n✅ Approved: ${approved.length}\n⚖️ Disputes: ${openDisputes.length}\n🚩 Flagged: ${flagged.length}\n❌ Failed notifs: ${failedNotifs.length}\n⏰ Upcoming deadlines: ${upcomingDeadlines.length}`);
  await audit('DAILY_DIGEST_SENT','admin','system','Daily digest sent');
  console.log('[CEE] Daily admin digest sent');
}
cron.schedule('0 7 * * *', () => runDailyAdminDigest().catch(e => console.error('[CEE] dailyAdminDigest error:',e)));

// ── replayAutoScheduler — 06:00 WAT = 05:00 UTC ──────────────────────────
async function runReplayAutoScheduler() {
  const seasonId=await getSeasonId(); if (!seasonId) return;
  const voided=await db.collection('fixtures').where('seasonId','==',seasonId).where('status','==','void').get();
  const allFix=await getFixtures(seasonId);
  const replayOrigIds=new Set(allFix.filter(f=>f.phase==='replay').map(f=>f.originalFixtureId));
  for (const doc of voided.docs) {
    if (replayOrigIds.has(doc.id)) continue;
    const f=doc.data(); if (!f.voidedAt) continue;
    const hoursElapsed=nowWAT().diff(fromTS(f.voidedAt),'hours').hours;
    if (hoursElapsed<24) continue;
    const players=await getPlayers(seasonId);
    await _generateWeekFixtures(seasonId,f.week||1,players,[{a:f.playerAId,b:f.playerBId}],{});
    await _sendMatchNotifications('REPLAY_SCHEDULED',doc.id,f.playerAId,f.playerBId,seasonId);
    const adminChat=env.telegram&&env.telegram.admin_chat_id;
    if (adminChat) await sendTelegram(adminChat,`⚙️ Replay auto-scheduled for fixture ${doc.id} (24hr admin fallback)`);
    console.log(`[CEE] Replay auto-scheduled for ${doc.id}`);
  }
}
cron.schedule('0 5 * * *', () => runReplayAutoScheduler().catch(e => console.error('[CEE] replayAutoScheduler error:',e)));

// ── notificationRetryWorker — every 2 hours — RES-1 + NOI-3 ─────────────
async function runNotificationRetryWorker() {
  const cutoff=toTS(nowWAT().minus({hours:24}));
  const failedSnap=await db.collection('notifications')
    .where('status','==','failed').where('retryCount','<',3).where('sentAt','>=',cutoff).get();
  if (failedSnap.empty){ console.log('[CEE] notificationRetryWorker: nothing to retry'); return; }
  const results=await Promise.allSettled(failedSnap.docs.map(async doc => {
    const n=doc.data(); const retryCount=(n.retryCount||0)+1;
    let success=false;
    try {
      if (n.channel==='telegram'||n.channel==='both') {
        if (n.telegramChatId&&n.messageText) { const r=await sendTelegram(n.telegramChatId,n.messageText); success=!!(r&&!r.error); }
        else if (n.recipientId) { const pd=await db.collection('players').doc(n.recipientId).get();
          if (pd.exists&&pd.data().telegramChatId) { const r=await sendTelegram(pd.data().telegramChatId,`📨 CEE: Retry of ${n.eventType} notification.`); success=!!(r&&!r.error); } }
      }
      if (n.channel==='email'||n.channel==='both') {
        if (n.email&&n.emailSubject&&n.emailHtmlBody) { const r=await sendEmail(n.email,n.emailSubject,n.emailHtmlBody); success=r.success; }
        else if (n.recipientId) { const pd=await db.collection('players').doc(n.recipientId).get();
          if (pd.exists&&pd.data().email) { const r=await sendEmail(pd.data().email,`CEE — Notification Retry (${n.eventType})`,`<p>This is a retry of a previously failed notification: <strong>${n.eventType}</strong></p>`); success=r.success; } }
      }
    } catch(e){ console.error(`[CEE] retry failed for ${doc.id}:`,e.message); }
    const newStatus=success?'sent':(retryCount>=3?'permanently_failed':'failed');
    await doc.ref.update({status:newStatus,retryCount,lastRetryAt:admin.firestore.FieldValue.serverTimestamp()});
  }));
  console.log(`[CEE] notificationRetryWorker: retried ${failedSnap.size}, succeeded ${results.filter(r=>r.status==='fulfilled').length}`);
}
cron.schedule('0 */2 * * *', () => runNotificationRetryWorker().catch(e => console.error('[CEE] notificationRetryWorker error:',e)));

// ═══════════════════════════════════════════════════════════════════════════
// FIRESTORE REAL-TIME LISTENERS
// Replaces onFixtureApproved + onRegistrationCreated Cloud Function triggers
// ═══════════════════════════════════════════════════════════════════════════

// In-memory map: fixtureId → last known adminApproved boolean.
// Reliably detects the false→true flip for EVERY approval path:
//   auto-approve (45min / 48hr flagged), manual admin approval, dispute resolution.
// Does NOT rely on autoApprovedAt, so manual approvals that never set
// autoApprovedAt are handled correctly.
// On server restart the map starts empty; the first onSnapshot pass populates
// it without triggering recalcs (we only act when we see a change from a
// previously known state, not on initial document load).
const _fixtureApprovalState = new Map();

db.collection('fixtures').onSnapshot(snapshot => {
  snapshot.docChanges().forEach(async change => {
    const docId   = change.doc.id;
    const current = change.doc.data();

    if (change.type === 'removed') {
      _fixtureApprovalState.delete(docId);
      return;
    }

    const prevApproved = _fixtureApprovalState.get(docId); // undefined on first sight
    const currApproved = current.adminApproved === true;

    // Always update map to current state
    _fixtureApprovalState.set(docId, currApproved);

    // prevApproved === undefined  → initial population on startup, do nothing
    // prevApproved === true       → was already approved, no flip
    // currApproved === false      → not approved yet, no action
    if (prevApproved === undefined) return;
    if (prevApproved === true)      return;
    if (!currApproved)              return;

    // adminApproved flipped false → true — mirrors onFixtureApproved exactly
    const seasonId = current.seasonId;
    if (!seasonId) return;
    console.log(`[CEE] onFixtureApproved: fixture ${docId} approved — recalculating standings`);
    await _recalcStandingsInternal(seasonId).catch(e => console.error('[CEE] listener recalc:', e));
    await _checkKnockoutQualification(seasonId).catch(e => console.error('[CEE] listener knockout:', e));

    // ── BROADCAST: notify ALL season players about this result ──────────────
    try {
      const hg = current.playerAGoals ?? 0, ag = current.playerBGoals ?? 0;
      const pAName = current.playerAName || 'Player A';
      const pBName = current.playerBName || 'Player B';
      const resultLine = `${pAName} ${hg} – ${ag} ${pBName}`;
      const winner = hg > ag ? pAName : ag > hg ? pBName : null;
      const tgMsg = `📊 <b>Match Result</b>\n\n${resultLine}\n${winner ? `🏆 Winner: <b>${winner}</b>` : '🤝 Draw'}\n\nStandings have been updated. Check the table!`;
      const allSnap = await db.collection('players').where('seasonId','==',seasonId).get();
      const broadcastPromises = [];
      allSnap.forEach(doc => {
        const p = doc.data(); const pid = doc.id;
        // Don't double-notify the two players in this fixture (they already get RESULT_APPROVED)
        if (pid === current.playerAId || pid === current.playerBId) return;
        // Telegram
        if (p.telegramChatId && p.notificationsTelegram !== false) {
          broadcastPromises.push(sendTelegram(p.telegramChatId, tgMsg).catch(()=>{}));
        }
        // Web Push
        if (p.pushSubscription && p.notificationsPush !== false) {
          let sub; try { sub = typeof p.pushSubscription==='string' ? JSON.parse(p.pushSubscription) : p.pushSubscription; } catch(e){ sub=null; }
          if (sub) broadcastPromises.push(_sendWebPush(sub, {
            title: '📊 CEE — Match Result',
            body: `${resultLine}${winner ? ` • ${winner} wins` : ' • Draw'}`,
            eventType: 'MATCH_RESULT_BROADCAST',
            data: { url: `${process.env.SITE_URL||'https://cee-esports.web.app'}#standings` }
          }).catch(()=>{}));
        }
      });
      await Promise.allSettled(broadcastPromises);
      console.log(`[CEE] Broadcast result to ${broadcastPromises.length} players for fixture ${docId}`);
    } catch(e) { console.error('[CEE] broadcast result error:', e.message); }
  });
}, err => console.error('[CEE] fixtures listener error:', err));

// Listen for new registrations → notify admin + player
// Skip the initial snapshot bulk load to avoid re-sending notifications for
// all existing registrations on every server restart (mirrors the behaviour of
// the original onRegistrationCreated Cloud Function trigger, which only fired
// for genuinely new writes).
let _isInitialRegistrationSnapshot = true;
db.collection('registrations').onSnapshot(snapshot => {
  if (_isInitialRegistrationSnapshot) {
    _isInitialRegistrationSnapshot = false;
    return; // ignore existing documents loaded on startup
  }
  snapshot.docChanges().forEach(async change => {
    if (change.type !== 'added') return;
    const reg   = change.doc.data();
    const regId = change.doc.id;
    const adminEmail = env.admin && env.admin.email;
    const adminChat  = env.telegram && env.telegram.admin_chat_id;
    if (adminEmail) sendEmail(adminEmail,'CEE — New Registration',
      `<p>📋 <strong>New registration received</strong></p>
       <div class="hl">
         <strong>${reg.gameName||reg.clubName||'Unknown'}</strong><br>
         Email: ${reg.email||'N/A'}<br>
         Registration ID: ${regId}
       </div>
       <p>Review in the Admin Panel → Players tab.</p>`).catch(()=>{});
    if (adminChat) sendTelegram(adminChat,
      `📋 <b>New registration</b>\n${reg.gameName||reg.clubName||'Unknown'}\nEmail: ${reg.email||'N/A'}`
    ).catch(()=>{});
    if (reg.email) sendEmail(reg.email,'CEE — Registration Received',
      `<p>✅ We've received your registration for <strong>Campus eSports Elite</strong>!</p>
       <div class="hl">
         <strong>What's next?</strong><br>
         Your application is under review. The admin will approve or reject your registration shortly.<br>
         You'll receive another email with your result and — if approved — your secure PIN.
       </div>
       <p>If you have any questions, contact the league admin.</p>`).catch(()=>{});
    logNotif(null,regId,'email','REGISTRATION_RECEIVED','sent').catch(()=>{});
  });
}, err => console.error('[CEE] registrations listener error:', err));


// ═══════════════════════════════════════════════════════════════════════════
// POST /analyzeOpponent — CEE Intelligence System
// Generates a scouting report on a player's upcoming opponent using stored
// matchStats and the 6-phase eFootball Analysis Engine via Gemini.
// Implements caching: report is reused until opponent plays a new match.
// ═══════════════════════════════════════════════════════════════════════════
app.post('/analyzeOpponent', async (req, res) => {
  // Disable nginx proxy buffering so Railway doesn't drop long responses
  res.setHeader('X-Accel-Buffering', 'no');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Keep-Alive', 'timeout=180');
  req.socket.setKeepAlive(true, 10000);
  req.socket.setTimeout(0); // disable socket timeout entirely for this endpoint
  const { requestingPlayerId, opponentPlayerId, seasonId, fixtureId } = req.body;
  if (!requestingPlayerId || !opponentPlayerId || !seasonId) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }

  // ── Auth: verify the requesting player via PIN header ───────────────────
  const pinHeader = req.headers['x-cee-player-pin'];
  if (pinHeader) {
    try {
      const secretDoc = await db.collection('playerSecrets').doc(requestingPlayerId).get();
      if (secretDoc.exists) {
        const secrets = secretDoc.data();
        if (secrets.pinHash) {
          const valid = await bcrypt.compare(pinHeader, secrets.pinHash);
          if (!valid) return res.status(401).json({ success: false, message: 'Authentication failed.' });
        }
      }
    } catch(authErr) { console.error('[CEE] analyzeOpponent auth error:', authErr.message); }
  }

  try {
    // ── Check if Intelligence feature is enabled ────────────────────────────
    const intelConfig = await db.collection('config').doc('intelligence').get();
    const analysisEnabled = !intelConfig.exists || intelConfig.data().analysisEnabled !== false;
    if (!analysisEnabled) {
      return res.json({ success: false, reason: 'disabled', message: 'Analysis feature temporarily unavailable. Check back soon.' });
    }

    // ── Fetch opponent match history (this season) ──────────────────────────
    const oppMatchSnap = await db.collection('matchStats')
      .where('playerId', '==', opponentPlayerId)
      .where('seasonId', '==', seasonId)
      .orderBy('verifiedAt', 'asc')
      .get();

    if (oppMatchSnap.empty) {
      return res.json({ success: false, reason: 'no_data', message: 'No match data available for this opponent yet. Check back after they play their first match.' });
    }

    const allOppMatches = [];
    oppMatchSnap.forEach(d => allOppMatches.push({ _id: d.id, ...d.data() }));
    const latestOppMatch = allOppMatches[allOppMatches.length - 1];

    // ── D2: Hybrid Cross-Season Memory ───────────────────────────────────────────
    // If opponent has < 3 matches this season, pull historical data so the scout
    // report has real context instead of being near-empty.
    //
    // TIER 1 (Identity-Linked): Check oppPlayer.linkedPreviousPlayerIds first.
    //   These are confirmed same-person matches from previous seasons, resolved by
    //   email/phone identity matching at registration time. Most accurate.
    //
    // TIER 2 (Season Fallback): If no identity links found, fall back to fetching
    //   matchStats by season number subtraction (season_N -> season_N-1).
    //   Works for first-season setups before identity linking is populated.
    //
    // All historical matches are labelled [PREVIOUS SEASON DATA] in the prompt
    // so Gemini weighs them as contextual background, not current-form data.
    let prevSeasonMatches = [];
    if (allOppMatches.length < 3) {
      try {
        const linkedIds = oppPlayer.linkedPreviousPlayerIds || [];

        if (linkedIds.length > 0) {
          // ── TIER 1: Identity-linked previous player IDs ───────────────────
          // Fetch across all previous linked player IDs (handles multi-season gaps,
          // tag changes, etc.) — up to 3 matches total, most recent first
          const batchSize = Math.min(linkedIds.length, 10); // Firestore 'in' limit
          const linkedSnap = await db.collection('matchStats')
            .where('playerId', 'in', linkedIds.slice(0, batchSize))
            .orderBy('verifiedAt', 'desc')
            .limit(3)
            .get();
          linkedSnap.forEach(d => prevSeasonMatches.push({
            _id: d.id, ...d.data(), _prevSeason: true, _linkMethod: 'identity'
          }));
          if (prevSeasonMatches.length > 0) {
            console.log(`[CEE] D2 TIER-1: ${prevSeasonMatches.length} identity-linked prev matches for ${opponentPlayerId}`);
          }
        }

        if (prevSeasonMatches.length === 0) {
          // ── TIER 2: Season number fallback ────────────────────────────────
          const currentSeasonNum = parseInt((seasonId.replace('season_', '') || '1'), 10);
          if (currentSeasonNum > 1) {
            const prevSeasonId = `season_${currentSeasonNum - 1}`;
            const fallbackSnap = await db.collection('matchStats')
              .where('playerId', '==', opponentPlayerId)
              .where('seasonId', '==', prevSeasonId)
              .orderBy('verifiedAt', 'desc')
              .limit(3)
              .get();
            fallbackSnap.forEach(d => prevSeasonMatches.push({
              _id: d.id, ...d.data(), _prevSeason: true, _linkMethod: 'season_fallback'
            }));
            if (prevSeasonMatches.length > 0) {
              console.log(`[CEE] D2 TIER-2: ${prevSeasonMatches.length} season-fallback prev matches for ${opponentPlayerId}`);
            }
          }
        }
      } catch(prevErr) { console.error('[CEE] D2 cross-season fetch error:', prevErr.message); }
    }

    // ── Cache check ─────────────────────────────────────────────────────────
    const reportDocId = `${requestingPlayerId}_${opponentPlayerId}_${seasonId}`;
    const cachedSnap = await db.collection('scoutReports').doc(reportDocId).get();
    let cachedReport = cachedSnap.exists ? cachedSnap.data() : null;

    // Also mark stale if report predates cross-season H2H (check for h2hRecord in prompt)
    const reportHasH2H = cachedReport && cachedReport.reportText && cachedReport.reportText.includes('H2H RECORD');
    if (cachedReport && cachedReport.opponentLastMatchId === latestOppMatch._id && reportHasH2H) {
      return res.json({
        success: true,
        cached: true,
        reportText: cachedReport.reportText,
        upgradeText: cachedReport.upgradeText,
        matchesAnalysed: cachedReport.matchesAnalysed,
        opponentName: cachedReport.opponentName || null,
        generatedAt: cachedReport.generatedAt ? cachedReport.generatedAt.toDate().toISOString() : null
      });
    }

    // ── Fetch requesting player match history (current + previous seasons) ──
    const myMatchSnap = await db.collection('matchStats')
      .where('playerId', '==', requestingPlayerId)
      .where('seasonId', '==', seasonId)
      .orderBy('verifiedAt', 'asc')
      .get();
    const myMatches = [];
    myMatchSnap.forEach(d => myMatches.push({ _id: d.id, ...d.data() }));

    // ── Fetch both player profiles ──────────────────────────────────────────
    const [reqPlayerDoc, oppPlayerDoc, oppProfileDoc, reqProfileDoc] = await Promise.all([
      db.collection('players').doc(requestingPlayerId).get(),
      db.collection('players').doc(opponentPlayerId).get(),
      db.collection('playerProfile').doc(opponentPlayerId).get(),
      db.collection('playerProfile').doc(requestingPlayerId).get()
    ]);
    const reqPlayer  = reqPlayerDoc.exists  ? { id: reqPlayerDoc.id,  ...reqPlayerDoc.data()  } : { id: requestingPlayerId, clubName: 'Unknown', gameName: 'Unknown', stats: {} };
    const oppPlayer  = oppPlayerDoc.exists  ? { id: oppPlayerDoc.id,  ...oppPlayerDoc.data()  } : { id: opponentPlayerId, clubName: 'Unknown', gameName: 'Unknown', stats: {} };
    const oppProfile = oppProfileDoc.exists ? oppProfileDoc.data() : null;
    const reqProfile = reqProfileDoc.exists ? reqProfileDoc.data() : null;

    // ── Cross-season H2H between requesting player and opponent ─────────────
    // Finds all matches across ALL seasons where these two faced each other,
    // using linkedPreviousPlayerIds for accurate identity matching.
    let h2hRecord = { wins:0, draws:0, losses:0, total:0, prevSeason:0, matches:[] };
    try {
      const myAllIds  = [requestingPlayerId, ...(reqPlayer.linkedPreviousPlayerIds || [])];
      const oppAllIds = [opponentPlayerId,   ...(oppPlayer.linkedPreviousPlayerIds || [])];
      const h2hSnap = await db.collection('matchStats')
        .where('playerId', 'in', myAllIds.slice(0, 10))
        .get();
      h2hSnap.forEach(doc => {
        const d = doc.data();
        if (!oppAllIds.includes(d.opponentId)) return;
        const isPrevSeason = d.seasonId !== seasonId;
        h2hRecord.total++;
        if (isPrevSeason) h2hRecord.prevSeason++;
        if (d.result === 'W') h2hRecord.wins++;
        else if (d.result === 'D') h2hRecord.draws++;
        else h2hRecord.losses++;
        h2hRecord.matches.push({
          result: d.result, goalsFor: d.goalsFor, goalsAgainst: d.goalsAgainst,
          seasonId: d.seasonId, matchDay: d.matchDay, isPrevSeason
        });
      });
    } catch(h2hErr) { /* non-fatal */ }

    // ── Pull requesting player's previous season matches if sparse this season ─
    if (myMatches.length < 3) {
      try {
        const myLinkedIds = reqPlayer.linkedPreviousPlayerIds || [];
        if (myLinkedIds.length > 0) {
          const myPrevSnap = await db.collection('matchStats')
            .where('playerId', 'in', myLinkedIds.slice(0, 10))
            .orderBy('verifiedAt', 'desc')
            .limit(5)
            .get();
          myPrevSnap.forEach(d => myMatches.push({ _id:d.id, ...d.data(), _prevSeason:true }));
        }
      } catch(e) { /* non-fatal */ }
    }

    // ── Use last 5 opponent matches ─────────────────────────────────────────
    const oppMatches = allOppMatches.slice(-5);
    const matchesAnalysed = oppMatches.length;

    // INTEL-05 FIX: Fetch the opposing player's matchStats doc for each fixture so the
    // opponent column in the Gemini prompt is filled with real numbers instead of all --.
    // Each matchStats doc is keyed as {fixtureId}_{playerId}, so the other side is
    // {fixtureId}_{m.opponentId} where m.opponentId is the other participant.
    const oppSideStatsMap = {};
    await Promise.allSettled(oppMatches.map(async m => {
      if (!m.fixtureId || !m.opponentId) return;
      try {
        const sideDoc = await db.collection('matchStats').doc(`${m.fixtureId}_${m.opponentId}`).get();
        if (sideDoc.exists) {
          oppSideStatsMap[m.fixtureId] = {
            stats:   sideDoc.data().stats   || {},
            context: sideDoc.data().context || {}
          };
        }
      } catch(e) { /* non-fatal: column stays -- */ }
    }));

    // ── Calculate requesting player averages ────────────────────────────────
    function _avg(arr, fn) {
      const vals = arr.map(fn).filter(v => v !== null && v !== undefined);
      return vals.length ? Math.round(vals.reduce((a,b) => a+b, 0) / vals.length) : null;
    }
    const myAvgPossession  = _avg(myMatches, m => m.stats && m.stats.possession);
    const myAvgPassAcc     = myMatches.length > 0 ? (() => {
      const vals = myMatches.map(m => {
        if (m.stats && m.stats.passes && m.stats.successfulPasses && m.stats.passes > 0)
          return Math.round((m.stats.successfulPasses / m.stats.passes) * 100);
        return null;
      }).filter(v => v !== null);
      return vals.length ? Math.round(vals.reduce((a,b) => a+b,0)/vals.length) : null;
    })() : null;
    const myAvgShots       = _avg(myMatches, m => m.stats && m.stats.shots);
    const myAvgShotsOnTarget = _avg(myMatches, m => m.stats && m.stats.shotsOnTarget);
    // Most common formation
    const formationCounts = {};
    myMatches.forEach(m => { if (m.context && m.context.formation) { const f = m.context.formation; formationCounts[f] = (formationCounts[f]||0)+1; } });
    const myFormation = Object.keys(formationCounts).sort((a,b) => formationCounts[b]-formationCounts[a])[0] || 'Unknown';
    const myAttackDir = (() => {
      const dirs = myMatches.map(m => m.context && m.context.attackDirection).filter(Boolean);
      const wingCount = dirs.filter(d => d === 'wings').length;
      return dirs.length ? (wingCount >= dirs.length/2 ? 'wings' : 'middle') : 'unknown';
    })();

    const reqStats = reqPlayer.stats || {};

    // ── Fetch tier data for both players ────────────────────────────────────
    const reqTier = reqPlayer.playerTier || null;
    const oppTier = oppPlayer.playerTier || null;
    const reqPR   = reqPlayer.performanceRating != null ? reqPlayer.performanceRating : null;
    const oppPR   = oppPlayer.performanceRating != null ? oppPlayer.performanceRating : null;
    const reqTierMatches = reqPlayer.tierMatchCount || 0;
    const oppTierMatches = oppPlayer.tierMatchCount || 0;

    // Tier labels for prompt injection
    const _tierLabel = (tier, pr, matchCount) => {
      if (!tier || matchCount < 4) return 'UNRANKED (fewer than 4 matches)';
      const emoji = tier === 'elite' ? '🔴 ELITE' : tier === 'mid' ? '🟡 MID' : '⚪ UNDERDOG';
      return `${emoji} (PR: ${pr !== null ? pr : '—'}, based on ${matchCount} matches)`;
    };
    const reqTierLabel = _tierLabel(reqTier, reqPR, reqTierMatches);
    const oppTierLabel = _tierLabel(oppTier, oppPR, oppTierMatches);

    // Matchup classification
    let tierMatchup = '';
    if (reqTier && oppTier && reqTierMatches >= 4 && oppTierMatches >= 4) {
      if (reqTier === oppTier)            tierMatchup = 'EVEN MATCHUP — Both players at same tier level';
      else if (reqTier === 'elite'  && oppTier !== 'elite')  tierMatchup = 'FAVOURITE — You are the higher-rated player in this fixture';
      else if (reqTier === 'underdog' && oppTier !== 'underdog') tierMatchup = 'UNDERDOG — You are the lower-rated player in this fixture';
      else if (oppTier === 'elite'  && reqTier !== 'elite')  tierMatchup = 'UNDERDOG — Your opponent is rated higher than you';
      else                                tierMatchup = 'CONTESTED — Slight tier gap but not decisive';
    } else {
      tierMatchup = 'UNCLASSIFIED — Insufficient match data for one or both players';
    }

    // ── TREND ENGINE — Opponent statistical trajectory analysis ─────────────
    // Uses chronologically ordered oppMatches (already slice(-5), oldest→newest).
    // Splits into first half and second half to detect improvement/decline.
    // All calculations are non-fatal — if data is thin, labels say "Insufficient data".
    const _trendAvg = (arr, fn) => {
      const vals = arr.map(fn).filter(v => v !== null && v !== undefined && !isNaN(v));
      return vals.length ? vals.reduce((a,b) => a+b, 0) / vals.length : null;
    };
    const _trendPassAcc = m => (m.stats && m.stats.passes > 0 && m.stats.successfulPasses != null)
      ? (m.stats.successfulPasses / m.stats.passes) * 100 : null;
    const _trendShotQual = m => (m.stats && m.stats.shots > 0 && m.stats.shotsOnTarget != null)
      ? (m.stats.shotsOnTarget / m.stats.shots) * 100 : null;
    const _trendGF = m => m.goalsFor != null ? m.goalsFor : null;
    const _trendGA = m => m.goalsAgainst != null ? m.goalsAgainst : null;
    const _trendPoss = m => (m.stats && m.stats.possession != null) ? m.stats.possession : null;
    const _trendShots = m => (m.stats && m.stats.shots != null) ? m.stats.shots : null;
    const _trendInter   = m => (m.stats && m.stats.interceptions != null) ? m.stats.interceptions : null;
    const _trendTackles = m => (m.stats && m.stats.tackles       != null) ? m.stats.tackles       : null;
    const _trendSaves   = m => (m.stats && m.stats.saves         != null) ? m.stats.saves         : null;
    const _trendCrosses = m => (m.stats && m.stats.crosses       != null) ? m.stats.crosses       : null;
    const _trendFouls   = m => (m.stats && m.stats.fouls         != null) ? m.stats.fouls         : null;
    const _trendOffsides= m => (m.stats && m.stats.offsides      != null) ? m.stats.offsides      : null;
    const _trendCorners = m => (m.stats && m.stats.cornerKicks   != null) ? m.stats.cornerKicks   : null;
    const _trendFKs     = m => (m.stats && m.stats.freeKicks     != null) ? m.stats.freeKicks     : null;

    // Split matches into early (first half) and recent (second half) for trajectory
    const trendMid = Math.ceil(oppMatches.length / 2);
    const trendEarly  = oppMatches.slice(0, trendMid);
    const trendRecent = oppMatches.slice(trendMid);

    const _trendDir = (_shortLabel, earlyVal, recentVal, label, higherIsBetter = true) => {
      if (earlyVal === null || recentVal === null) return `${label}: Insufficient data`;
      const eNum = typeof earlyVal === 'number' ? earlyVal : parseFloat(earlyVal);
      const rNum = typeof recentVal === 'number' ? recentVal : parseFloat(recentVal);
      if (isNaN(eNum) || isNaN(rNum)) return `${label}: Insufficient data`;
      const diff = rNum - eNum;
      const pct  = eNum !== 0 ? Math.round(Math.abs(diff) / Math.abs(eNum) * 100) : 0;
      if (Math.abs(diff) < 0.5) return `${label}: Stable (${rNum.toFixed(1)})`;
      const improving = higherIsBetter ? diff > 0 : diff < 0;
      const arrow = improving ? '↑ IMPROVING' : '↓ DECLINING';
      return `${label}: ${arrow} ${eNum.toFixed(1)} → ${rNum.toFixed(1)} (${pct}% shift)`;
    };

    // Results sequence for streak analysis
    const resultSeq = oppMatches.map(m => m.result || '?');
    const recentResults = resultSeq.slice(-3);
    const wins3   = recentResults.filter(r => r === 'W').length;
    const losses3  = recentResults.filter(r => r === 'L').length;
    let formStreak = '';
    if (wins3 === 3)        formStreak = '🔥 HOT STREAK — Won last 3';
    else if (wins3 === 2)   formStreak = '📈 Good form — 2 of last 3 won';
    else if (losses3 === 3) formStreak = '❄️ COLD STREAK — Lost last 3';
    else if (losses3 === 2) formStreak = '📉 Poor form — Lost 2 of last 3';
    else                    formStreak = '〰 Mixed form — No clear streak';

    // Formation stability
    const oppFormations = oppMatches.map(m => m.context && m.context.formation).filter(Boolean);
    const oppFormSet = [...new Set(oppFormations)];
    let formationStability = '';
    if (oppFormations.length === 0)       formationStability = 'No formation data recorded';
    else if (oppFormSet.length === 1)     formationStability = `Rigid — always plays ${oppFormSet[0]}`;
    else if (oppFormSet.length === 2)     formationStability = `Dual setup — alternates ${oppFormSet.join(' / ')}`;
    else                                  formationStability = `Tactical variety — used ${oppFormSet.join(', ')}`;

    // Scoring pattern: goals per match trend
    const earlyGF   = _trendAvg(trendEarly,  _trendGF);
    const recentGF  = _trendAvg(trendRecent, _trendGF);
    const earlyGA   = _trendAvg(trendEarly,  _trendGA);
    const recentGA  = _trendAvg(trendRecent, _trendGA);
    const earlyPassAcc  = _trendAvg(trendEarly,  _trendPassAcc);
    const recentPassAcc = _trendAvg(trendRecent, _trendPassAcc);
    const earlyShotQ    = _trendAvg(trendEarly,  _trendShotQual);
    const recentShotQ   = _trendAvg(trendRecent, _trendShotQual);
    const earlyPoss     = _trendAvg(trendEarly,  _trendPoss);
    const recentPoss    = _trendAvg(trendRecent, _trendPoss);
    const earlyShots    = _trendAvg(trendEarly,  _trendShots);
    const recentShots   = _trendAvg(trendRecent, _trendShots);
    const earlyInter    = _trendAvg(trendEarly,  _trendInter);
    const recentInter   = _trendAvg(trendRecent, _trendInter);
    const earlyTackles  = _trendAvg(trendEarly,  _trendTackles);
    const recentTackles = _trendAvg(trendRecent, _trendTackles);
    const earlySaves    = _trendAvg(trendEarly,  _trendSaves);
    const recentSaves   = _trendAvg(trendRecent, _trendSaves);
    const earlyCrosses  = _trendAvg(trendEarly,  _trendCrosses);
    const recentCrosses = _trendAvg(trendRecent, _trendCrosses);
    const earlyFouls    = _trendAvg(trendEarly,  _trendFouls);
    const recentFouls   = _trendAvg(trendRecent, _trendFouls);
    const earlyOffsides = _trendAvg(trendEarly,  _trendOffsides);
    const recentOffsides= _trendAvg(trendRecent, _trendOffsides);
    const earlyCorners  = _trendAvg(trendEarly,  _trendCorners);
    const recentCorners = _trendAvg(trendRecent, _trendCorners);
    const earlyFKs      = _trendAvg(trendEarly,  _trendFKs);
    const recentFKs     = _trendAvg(trendRecent, _trendFKs);

    // ── Behavioural patterns from questionnaire data ──────────────────────────
    const _ctxCount = (field) => oppMatches.filter(m => m.context && m.context[field] === true).length;
    const scoredFirstCount   = _ctxCount('scoredFirst');
    const setpieceGoalCount  = _ctxCount('setpieceGoal');
    const momentumShiftCount = _ctxCount('momentumShift');
    const subsCount          = _ctxCount('madeSubstitutions');
    const selfMistakeCount   = _ctxCount('selfMistakeGoal');
    const _bp = oppMatches.length;
    const _pct = (n) => _bp > 0 ? `${n}/${_bp} matches` : 'No data';
    const behaviouralPatterns = [
      scoredFirstCount   >= Math.ceil(_bp*0.6) ? `Scores first in ${_pct(scoredFirstCount)} -- front-loaded game style, aggressive in opening phases` :
      scoredFirstCount   <= Math.floor(_bp*0.2) && _bp >= 3 ? `Rarely scores first (${_pct(scoredFirstCount)}) -- often plays from behind, may sit back early` : null,
      setpieceGoalCount  >= 2 ? `Set piece goals in ${_pct(setpieceGoalCount)} -- dangerous from free kicks and corners, defend them tightly` : null,
      momentumShiftCount >= 2 ? `Momentum shifts felt in ${_pct(momentumShiftCount)} -- second half vulnerability detected, press harder when leading` : null,
      selfMistakeCount   >= 2 ? `Self-mistake goals in ${_pct(selfMistakeCount)} -- error-prone under pressure, press high and force mistakes` : null,
      subsCount          >= Math.ceil(_bp*0.6) ? `Uses substitutions in ${_pct(subsCount)} -- rotation-dependent, watch for mid-game formation changes` : null,
    ].filter(Boolean);

    // Weighted overall form score (recent matches count double)
    const oppAllGoalsFor = oppMatches.map(_trendGF).filter(v => v !== null);
    const oppAllGoalsAgainst = oppMatches.map(_trendGA).filter(v => v !== null);
    const oppTotalGF = oppAllGoalsFor.reduce((a,b) => a+b, 0);
    const oppTotalGA = oppAllGoalsAgainst.reduce((a,b) => a+b, 0);
    const oppGD = oppTotalGF - oppTotalGA;

    // Context trend: are they pressing more / sitting back more recently?
    const recentPressing  = oppMatches.slice(-3).filter(m => m.context && m.context.opponentPressing === true).length;
    const recentDefensive = oppMatches.slice(-3).filter(m => m.context && m.context.opponentDefensive === true).length;
    let tacticalTrend = '';
    if (recentPressing >= 2)       tacticalTrend = 'Increasingly aggressive — pressing more in recent matches';
    else if (recentDefensive >= 2) tacticalTrend = 'Increasingly cautious — sitting deeper in recent matches';
    else                           tacticalTrend = 'No clear tactical shift detected in recent matches';

    // Assemble trend report block to inject into prompt
    const TREND_REPORT = `
════════════════════════════════════════════════════════════════
TREND ANALYSIS ENGINE — ${oppPlayer.clubName} TRAJECTORY REPORT
(${oppMatches.length} matches analysed chronologically, oldest → newest)
════════════════════════════════════════════════════════════════

FORM STREAK:       ${formStreak}
RESULT SEQUENCE:   ${resultSeq.join(' → ')} (W=Win D=Draw L=Loss)
SEASON RECORD:     ${oppTotalGF} scored / ${oppTotalGA} conceded / GD ${oppGD >= 0 ? '+' : ''}${oppGD}

STATISTICAL TRAJECTORY (Early matches → Recent matches):
  ${_trendDir('Goals scored/match',    earlyGF,      recentGF,      'GOALS SCORED/MATCH',   true)}
  ${_trendDir('Goals conceded/match',  earlyGA,      recentGA,      'GOALS CONCEDED/MATCH',  false)}
  ${_trendDir('Pass accuracy',         earlyPassAcc, recentPassAcc, 'PASS ACCURACY %',       true)}
  ${_trendDir('Shot quality',          earlyShotQ,   recentShotQ,   'SHOT QUALITY RATIO %',  true)}
  ${_trendDir('Possession',            earlyPoss,    recentPoss,    'POSSESSION %',          true)}
  ${_trendDir('Shots per match',       earlyShots,   recentShots,   'SHOTS/MATCH',           true)}
  ${_trendDir('Interceptions/match',   earlyInter,   recentInter,   'INTERCEPTIONS/MATCH',   true)}
  ${_trendDir('Tackles/match',         earlyTackles, recentTackles, 'TACKLES/MATCH',         true)}
  ${_trendDir('Saves/match',           earlySaves,   recentSaves,   'SAVES/MATCH',           false)}
  ${_trendDir('Crosses/match',         earlyCrosses, recentCrosses, 'CROSSES/MATCH',         true)}
  ${_trendDir('Fouls/match',           earlyFouls,   recentFouls,   'FOULS/MATCH',           false)}
  ${_trendDir('Offsides/match',        earlyOffsides,recentOffsides,'OFFSIDES/MATCH',        false)}
  ${_trendDir('Corners/match',         earlyCorners, recentCorners, 'CORNERS/MATCH',         true)}
  ${_trendDir('Free kicks/match',      earlyFKs,     recentFKs,     'FREE KICKS/MATCH',      false)}

FORMATION PATTERN: ${formationStability}
TACTICAL TREND:    ${tacticalTrend}

BEHAVIOURAL PATTERNS (from post-match questionnaire data):
${behaviouralPatterns.length > 0 ? behaviouralPatterns.map(b => '  * ' + b).join('\n') : '  * Insufficient questionnaire data -- players have not completed post-match questions'}

INTERPRETATION RULES FOR TREND DATA:
- ↑ IMPROVING in goals scored + ↑ shot quality = player is peaking — treat as current threat level
- ↓ DECLINING in pass accuracy = build-up is breaking down — pressing their midfield may force errors
- HOT STREAK opponent is psychologically confident — expect aggressive pressing mentality
- COLD STREAK opponent may be desperate — higher risk of erratic play or tactical changes
- Formation variety = adaptable player; rigid formation = predictable but potentially optimised
- Increasing defensiveness (tactical trend) = they may be protecting a lead or lacking confidence
- TACKLES trending up = defending more, likely sitting deeper or under sustained pressure
- SAVES trending up = goalkeeper overworked = your attacks creating real danger, keep attacking
- CROSSES trending up = exploiting wide areas = pack the box, use aerial presence
- FOULS trending up = frustration or reckless pressing = set pieces are a real threat
- OFFSIDES trending up = running a high defensive line = through balls and runs in behind will hurt them
- CORNERS trending up = dominant wide play = strong aerial game, be physical at set pieces
- Behavioural patterns marked * are derived from player post-match questionnaire submissions
════════════════════════════════════════════════════════════════`;

    // ── eFootball Mechanics knowledge base ─────────────────────────────────
    // ── eFootball Analysis Engine v2 (5 Phases + Tactical Upgrade Sub-Prompt) ─
    const ANALYSIS_ENGINE_V2 = `You are an expert eFootball Mobile scout analyst. Analyse the match statistics below and produce a SCOUTING REPORT with exactly these 9 sections. Be sharp, specific, and ground every finding in eFootball mechanics (attacking styles, defensive styles, sliders, player roles).

SECTION 1 — MATCH SNAPSHOT
2-3 sentences. What style did each team run? Was the result earned or fortunate?

SECTION 2 — STAT-BY-STAT BREAKDOWN
For every stat: raw numbers, what it means in eFootball, which team it favours. Calculate pass accuracy % and shot quality ratio (shots on target ÷ shots).

SECTION 3 — ATTACKING SYSTEM VERDICT
Each team: inferred attacking style with stat evidence. Execution rating: SURGICAL / EFFICIENT / WASTEFUL / TOOTHLESS.

SECTION 4 — DEFENSIVE SYSTEM VERDICT
Each team: inferred defensive style with stat evidence. Rating: FORTRESS / DISCIPLINED / LEAKY / EXPOSED. Flag any dangerous matchup.

SECTION 5 — POSSESSION QUALITY
Pass accuracy for both teams. Was possession productive or sterile? What sliders likely contributed?

SECTION 6 — DOMINANCE SCORE & RESULT FAIRNESS
Score each team 0-10 using: +2 shot quality ≥60%, +2 pass accuracy ≥80%, +1 more interceptions, +1 more tackles, +2 more shots on target, +1 possession >52%, +1 crosses led to shots. Verdict: RESULT REFLECTS PLAY / RESULT FLATTERS [team] / UNLUCKY LOSER DETECTED.

SECTION 7 — KEY TACTICAL INSIGHTS
4-6 bullet points. Each must reference a specific stat AND a specific eFootball mechanic.

SECTION 8 — TREND VERDICT & FORM READING
Using the TREND DATA provided: is opponent improving/declining/stable? FORM RATING: PEAK / GOOD / INCONSISTENT / OUT OF FORM. Name 2 biggest trend risks and 1 exploit.

SECTION 9 — WHAT TO ADJUST (for the requesting player's team)
Minimum 3 adjustments in this format:
PROBLEM → [stat finding]
CAUSE → [likely eFootball setting]
FIX → [exact setting: style name, slider value 1-10, player role, or formation]

[MATCH DATA BELOW]
[PASTE YOUR eFOOTBALL MATCH STATISTICS BELOW THIS LINE]`
    // ── Tactical Upgrade Engine v2 (Sub-Prompt) ──────────────────────────────
    const UPGRADE_ENGINE_V2 = `You are an eFootball Mobile tactical coach. Based on the scouting report below, produce a TACTICAL UPGRADE PLAN.

Every recommendation must reference a real eFootball setting: attacking style, defensive style, slider value (1-10), player role name, or formation.

FORMAT:
┌─────────────────────────────────────────┐
│  TACTICAL UPGRADE PLAN                  │
└─────────────────────────────────────────┘

PRIORITY FIXES (do before next match):
① [Most critical — exact setting + value]
② [Second fix]  
③ [Third fix]

SECONDARY ADJUSTMENTS:
· [Fine-tuning adjustment]
· [Fine-tuning adjustment]

IN-MATCH TRIGGERS:
· If [situation] → [specific setting change]
· If [situation] → [specific setting change]

CONDITION CHECK:
· [Position] — only start on gold/green form
· [Position] — bench if yellow/red form

[PASTE YOUR eFOOTBALL MATCH STATISTICS BELOW THIS LINE]`
    // ── Build prompt blocks ─────────────────────────────────────────────────
    // Block 4: Requesting player context
    // ── Build stats table for each opponent match ─────────────────────────
    const fmtN = v => (v !== null && v !== undefined) ? v : '—';

    // Build the stats table rows — one table per match, injected at Phase 5 slot
    let matchTables = '';
    oppMatches.forEach((m, idx) => {
      const s   = m.stats   || {};
      const ctx = m.context || {};
      const passAcc = (s.passes && s.successfulPasses)
        ? Math.round((s.successfulPasses / s.passes) * 100) + '%'
        : '—';
      const shotQual = (s.shots && s.shotsOnTarget)
        ? Math.round((s.shotsOnTarget / s.shots) * 100) + '%'
        : '—';

      // INTEL-05 FIX: pull opponent-side stats from oppSideStatsMap (fetched above)
      const oppSide = oppSideStatsMap[m.fixtureId] || {};
      const os   = oppSide.stats   || {};
      const octx = oppSide.context || {};
      const oppPassAcc = (os.passes && os.successfulPasses)
        ? Math.round((os.successfulPasses / os.passes) * 100) + '%'
        : '—';
      const oppShotQual = (os.shots && os.shotsOnTarget)
        ? Math.round((os.shotsOnTarget / os.shots) * 100) + '%'
        : '—';

      matchTables += `
────────────────────────────────────────────────────────────────
MATCH ${idx+1} OF ${matchesAnalysed} — Match Day ${m.matchDay||'?'} — Result: ${m.result||'?'} (${m.goalsFor||0}–${m.goalsAgainst||0})
────────────────────────────────────────────────────────────────

  My Team: ${oppPlayer.clubName}   Score: ${m.goalsFor||0} – ${m.goalsAgainst||0}   Opponent: [opponent]

  Stat                | My Team  | Opponent
  --------------------|----------|----------
  Possession          | ${fmtN(s.possession)}%     | ${fmtN(100-(s.possession||0))}%
  Shots               | ${fmtN(s.shots)}        | ${fmtN(os.shots)}
  Shots on Target     | ${fmtN(s.shotsOnTarget)}        | ${fmtN(os.shotsOnTarget)}
  Fouls               | ${fmtN(s.fouls)}        | ${fmtN(os.fouls)}
  Offsides            | ${fmtN(s.offsides)}        | ${fmtN(os.offsides)}
  Corner Kicks        | ${fmtN(s.cornerKicks)}        | ${fmtN(os.cornerKicks)}
  Free Kicks          | ${fmtN(s.freeKicks)}        | ${fmtN(os.freeKicks)}
  Passes              | ${fmtN(s.passes)}        | ${fmtN(os.passes)}
  Successful Passes   | ${fmtN(s.successfulPasses)}        | ${fmtN(os.successfulPasses)}
  Crosses             | ${fmtN(s.crosses)}        | ${fmtN(os.crosses)}
  Interceptions       | ${fmtN(s.interceptions)}        | ${fmtN(os.interceptions)}
  Tackles             | ${fmtN(s.tackles)}        | ${fmtN(os.tackles)}
  Saves               | ${fmtN(s.saves)}        | ${fmtN(os.saves)}

  Calculated:
  Pass Accuracy       : ${passAcc}        | ${oppPassAcc}
  Shot Quality Ratio  : ${shotQual}        | ${oppShotQual}

  [OPTIONAL — context supplied by player]
  My Attacking Style  : ${ctx.attackDirection === 'wings' ? 'Out Wide (wings)' : ctx.attackDirection === 'middle' ? 'Center Attack (middle)' : 'unknown'}
  My Formation        : ${ctx.formation || 'unknown'}
  Opponent pressing   : ${ctx.opponentPressing === true ? 'yes — Frontline Pressure or Aggressive likely' : ctx.opponentPressing === false ? 'no' : 'unknown'}
  Opponent sat back   : ${ctx.opponentDefensive === true ? 'yes — Deep Defensive Line or Possession Trap likely' : ctx.opponentDefensive === false ? 'no' : 'unknown'}
  Scored first        : ${ctx.scoredFirst === true ? 'yes' : ctx.scoredFirst === false ? 'no' : 'unknown'}
  Out of position     : ${ctx.outOfPositionPlayers === true ? 'yes' : ctx.outOfPositionPlayers === false ? 'no' : 'unknown'}
  Set piece goal      : ${ctx.setpieceGoal === true ? 'yes' : ctx.setpieceGoal === false ? 'no' : 'unknown'}
  Momentum shift felt : ${ctx.momentumShift === true ? 'yes [MOMENTUM-POSSIBLE elevated to CONFIRMED]' : ctx.momentumShift === false ? 'no' : 'unknown'}
  Made substitutions  : ${ctx.madeSubstitutions === true ? 'yes' : ctx.madeSubstitutions === false ? 'no' : 'unknown'}
  Self-mistake goal   : ${ctx.selfMistakeGoal === true ? 'yes' : ctx.selfMistakeGoal === false ? 'no' : 'unknown'}

  [OPPONENT CONTEXT for this match -- from their post-match questionnaire]
  Opponent formation  : ${octx.formation || 'unknown'}
  Opponent attack dir : ${octx.attackDirection === 'wings' ? 'Out Wide (wings)' : octx.attackDirection === 'middle' ? 'Center Attack (middle)' : 'unknown'}
  Opponent pressed    : ${octx.opponentPressing  === true ? 'yes -- likely Frontline Pressure or Aggressive' : octx.opponentPressing  === false ? 'no' : 'unknown'}
  Opponent sat back   : ${octx.opponentDefensive === true ? 'yes -- likely Deep Line or Possession Trap'     : octx.opponentDefensive === false ? 'no' : 'unknown'}
`;
    });

    // ── D2: Append previous season match tables if fetched ───────────────────────
    if (prevSeasonMatches.length > 0) {
      matchTables += `
[PREVIOUS SEASON DATA -- ${prevSeasonMatches[0]&&prevSeasonMatches[0]._linkMethod==='identity' ? 'identity-verified returning player' : 'same-ID previous season'} -- use as background context; current season data limited to ${allOppMatches.length} match${allOppMatches.length !== 1 ? 'es' : ''}]
`;
      prevSeasonMatches.forEach((m, idx) => {
        const s   = m.stats   || {};
        const ctx = m.context || {};
        const passAcc  = (s.passes && s.successfulPasses) ? Math.round((s.successfulPasses/s.passes)*100)+'%' : '—';
        const shotQual = (s.shots  && s.shotsOnTarget)    ? Math.round((s.shotsOnTarget/s.shots)*100)+'%'     : '—';
        matchTables += `
────────────────────────────────────────────────────────────────
PREV SEASON MATCH ${idx+1} — Match Day ${m.matchDay||'?'} — Result: ${m.result||'?'} (${m.goalsFor||0}–${m.goalsAgainst||0}) [PREVIOUS SEASON]
────────────────────────────────────────────────────────────────

  My Team: ${oppPlayer.clubName}   Score: ${m.goalsFor||0} – ${m.goalsAgainst||0}   [Previous Season]

  Stat                | My Team  | Opponent
  --------------------|----------|----------
  Possession          | ${fmtN(s.possession)}%     | ${fmtN(100-(s.possession||0))}%
  Shots               | ${fmtN(s.shots)}        | —
  Shots on Target     | ${fmtN(s.shotsOnTarget)}        | —
  Passes              | ${fmtN(s.passes)}        | —
  Successful Passes   | ${fmtN(s.successfulPasses)}        | —
  Interceptions       | ${fmtN(s.interceptions)}        | —
  Tackles             | ${fmtN(s.tackles)}        | —

  Pass Accuracy       : ${passAcc}
  Shot Quality Ratio  : ${shotQual}
  Formation           : ${ctx.formation || 'unknown'}
  Attack direction    : ${ctx.attackDirection || 'unknown'}
`;
      });
    }

    // ── Section 9 personalisation anchor (Section 8 = Trend Verdict) ──────────
    const section8Anchor = `════════════════════════════════════════════════════════════════
PLAYER TIER & CONTEXT — READ BEFORE WRITING ANY SECTION
════════════════════════════════════════════════════════════════

${oppProfile && oppProfile.fingerprintText ? oppProfile.fingerprintText + '\n' : ''}
REQUESTING PLAYER  : ${reqPlayer.clubName} (${reqPlayer.gameName})
  Tier             : ${reqTierLabel}
  Formation        : ${myFormation}
  Attack style     : ${myAttackDir}
  Avg pass accuracy: ${myAvgPassAcc !== null ? myAvgPassAcc+'%' : 'N/A'}
  Avg shots/match  : ${myAvgShots !== null ? myAvgShots : 'N/A'}

OPPONENT SCOUTED   : ${oppPlayer.clubName}
  Tier             : ${oppTierLabel}
  Playstyle        : ${oppProfile ? oppProfile.fingerprintText || 'No fingerprint yet' : 'No profile yet'}

YOUR PROFILE       : ${reqPlayer.clubName}
  Playstyle        : ${reqProfile ? reqProfile.fingerprintText || 'No fingerprint yet' : 'No profile yet'}

DIRECT H2H RECORD  : ${h2hRecord.total > 0
  ? `${reqPlayer.clubName} vs ${oppPlayer.clubName} — ${h2hRecord.wins}W ${h2hRecord.draws}D ${h2hRecord.losses}L across ${h2hRecord.total} match(es)`
    + (h2hRecord.prevSeason > 0 ? ` (${h2hRecord.prevSeason} from previous season — identity verified)` : '') 
    + (h2hRecord.matches.slice(0,3).map(m => `\n  [${ m.isPrevSeason ? m.seasonId : 'this season' }] ${m.result} ${m.goalsFor}–${m.goalsAgainst} MD${m.matchDay||'?'}`).join(''))
  : 'No previous meetings between these two players'}

FIXTURE MATCHUP    : ${tierMatchup}

TIER-BASED ANALYSIS RULES:
- UNDERDOG vs ELITE: Do NOT give generic advice. The underdog needs realistic
  upset paths — which specific weaknesses in the elite player's stats can be
  exploited? What low-risk setup limits the elite player's strengths?
  Frame the analysis as: "Here is how you compete, not just how you survive."
- ELITE vs UNDERDOG: Warn against complacency. Flag if the underdog has any
  improving trends that make them more dangerous than their tier suggests.
- EVEN MATCHUP: Emphasise fine margins — the difference will come from
  tactical adjustments, not raw ability. Identify the 1-2 stats that will
  be decisive.
- UNCLASSIFIED: Base analysis purely on match data available. Do not reference
  tier labels if data is insufficient.

SECTION 9 "WHAT TO ADJUST" must be written for the REQUESTING PLAYER.
Write as: "Here is what ${reqPlayer.clubName} should do to beat ${oppPlayer.clubName}."
Every PROBLEM / CAUSE / FIX must be from ${reqPlayer.clubName}'s perspective.
════════════════════════════════════════════════════════════════`;

    // ── CALL 1: Full prompt — engine first, stats at Phase 5 slot ────────────
    // The engine ends with the [PASTE] marker — we inject the stats right there.
    const fullPrompt = ANALYSIS_ENGINE_V2.replace(
      '[PASTE YOUR eFOOTBALL MATCH STATISTICS BELOW THIS LINE]',
      `[CEE SCOUTING MODE — AUTOMATED STAT INJECTION]

You are performing a CROSS-MATCH SCOUTING ANALYSIS.
You are NOT analysing your own match. You are scouting: ${oppPlayer.clubName}
This report will be read by: ${reqPlayer.clubName}

The stats below are ${oppPlayer.clubName}'s verified match records — ${matchesAnalysed} match(es) this season.
In each table, "My Team" = ${oppPlayer.clubName}.

For patterns appearing in 2+ matches: treat as CONFIRMED TENDENCY.
For patterns appearing in only 1 match: label [SINGLE-MATCH — VERIFY].

${section8Anchor}

${TREND_REPORT}

${matchTables}
════════════════════════════════════════════════════════════════`
    );

    // ── CALL 2: Upgrade Engine — engine first, analysis injected at output slot
    const upgradeSubPrompt = UPGRADE_ENGINE_V2.replace(
      'TACTICAL UPGRADE PLAN — [Match Result]',
      `TACTICAL UPGRADE PLAN — ${reqPlayer.clubName} vs ${oppPlayer.clubName}`
    ) + `

════════════════════════════════════════════════════════════════
MATCH ANALYSIS TO USE AS EVIDENCE BASE:
════════════════════════════════════════════════════════════════
Requesting player : ${reqPlayer.clubName} | Formation: ${myFormation} | Attack: ${myAttackDir} | Avg pass acc: ${myAvgPassAcc !== null ? myAvgPassAcc+'%' : 'N/A'}
Opponent scouted  : ${oppPlayer.clubName} | Matches analysed: ${matchesAnalysed}

Every fix in the upgrade plan must be actionable for ${reqPlayer.clubName} specifically.
H2H history: ${h2hRecord.total > 0 ? `${h2hRecord.wins}W ${h2hRecord.draws}D ${h2hRecord.losses}L in ${h2hRecord.total} meeting(s)` : 'First time meeting'}
`;

    // ── Call 1 — Main Analysis ──────────────────────────────────────────────
    let reportText = '';
    try {
      const _gr1 = await _geminiPost({
          contents: [{ parts: [{ text: fullPrompt }] }],
          generationConfig: { maxOutputTokens:8000, temperature: 0 }
        });
      if (!_gr1.ok) throw new Error(_gr1.error || 'Gemini Call 1 failed');
      reportText = (_gr1.data.candidates&&_gr1.data.candidates[0]&&_gr1.data.candidates[0].content&&_gr1.data.candidates[0].content.parts&&_gr1.data.candidates[0].content.parts[0]&&_gr1.data.candidates[0].content.parts[0].text) || '';
      if (!reportText) throw new Error('Gemini Call 1 returned empty response');
    } catch(e1) {
      console.error('[CEE] analyzeOpponent Call 1 error:', e1.message);
      // If cached report exists, serve as fallback
      if (cachedReport && cachedReport.reportText) {
        return res.json({ success: false, reason: 'ai_unavailable', message: 'Analysis engine temporarily unavailable. Your cached report has been returned.', reportText: cachedReport.reportText, upgradeText: cachedReport.upgradeText || '', cached: true });
      }
      return res.json({ success: false, reason: 'ai_unavailable', message: 'Analysis engine is temporarily unavailable. Please try again shortly.' });
    }

    // ── Cache the report (upgrade plan fetched separately by frontend via /analyzeOpponentUpgrade) ──
    const reportDoc = {
      requestingPlayerId, opponentPlayerId, seasonId,
      generatedAt: admin.firestore.FieldValue.serverTimestamp(),
      opponentLastMatchId: latestOppMatch._id,
      reportText,
      upgradeText: '',
      matchesAnalysed,
      opponentName: oppPlayer.clubName || oppPlayer.gameName || 'Unknown'
    };
    await db.collection('scoutReports').doc(reportDocId).set(reportDoc);

    // Update intelligence stats in config
    db.collection('config').doc('intelligence').set({
      lastGeminiCallAt: admin.firestore.FieldValue.serverTimestamp(),
      reportsGeneratedTotal: admin.firestore.FieldValue.increment(1)
    }, { merge: true }).catch(() => {});

    console.log(`[CEE] Scout report generated: ${reqPlayer.clubName} scouting ${oppPlayer.clubName} (${matchesAnalysed} matches analysed)`);

    return res.json({
      success: true,
      cached: false,
      reportText,
      upgradeText: '',
      matchesAnalysed,
      opponentName: oppPlayer.clubName || oppPlayer.gameName,
      generatedAt: new Date().toISOString()
    });

  } catch(e) {
    console.error('[CEE] analyzeOpponent error:', e.message);
    return res.status(500).json({ success: false, message: 'Server error: ' + e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /analyzeOpponentUpgrade — Call 2 only (Tactical Upgrade Plan)
// Called separately after /analyzeOpponent to avoid Railway timeout
// ═══════════════════════════════════════════════════════════════════════════
app.post('/analyzeOpponentUpgrade', async (req, res) => {
  res.setHeader('X-Accel-Buffering', 'no');
  res.setHeader('Connection', 'keep-alive');
  req.socket.setKeepAlive(true, 10000);
  req.socket.setTimeout(0);
  const { reportText, requestingPlayerName, opponentName, myFormation, myAttackDir, myAvgPassAcc, matchesAnalysed } = req.body;
  if (!reportText) return res.status(400).json({ success: false, message: 'Missing reportText' });
  try {
    const upgradeSubPrompt = `You are an eFootball Mobile tactical coach.
Based on the match analysis report below, produce a TACTICAL UPGRADE PLAN with specific eFootball settings changes.

FORMAT:
PRIORITY FIXES (before next match):
① [Fix 1 — style/slider/role + exact value]
② [Fix 2]
③ [Fix 3]

SECONDARY ADJUSTMENTS:
· [Adjustment 1]
· [Adjustment 2]

IN-MATCH TRIGGERS:
· If [situation] → [specific adjustment]

Every recommendation must reference a real eFootball setting (attacking style, defensive style, slider value 1-10, player role name, or formation).

Requesting player: ${requestingPlayerName || 'unknown'} | Formation: ${myFormation || 'unknown'} | Attack: ${myAttackDir || 'unknown'} | Avg pass acc: ${myAvgPassAcc || 'N/A'}
Opponent scouted: ${opponentName || 'unknown'} | Matches analysed: ${matchesAnalysed || '?'}

MATCH ANALYSIS:
`;
    const _gr2 = await _geminiPost({
      contents: [{ parts: [{ text: upgradeSubPrompt + reportText }] }],
      generationConfig: { maxOutputTokens: 8000, temperature: 0 }
    });
    const upgradeText = (_gr2.ok && _gr2.data.candidates&&_gr2.data.candidates[0]&&_gr2.data.candidates[0].content&&_gr2.data.candidates[0].content.parts&&_gr2.data.candidates[0].content.parts[0]&&_gr2.data.candidates[0].content.parts[0].text) || '';
    return res.json({ success: true, upgradeText });
  } catch(e) {
    console.error('[CEE] analyzeOpponentUpgrade error:', e.message);
    return res.json({ success: false, upgradeText: '', message: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// GET /getMatchProbabilities — Match Probability Engine
// Calculates win probability for every fixture where both players have 4+
// verified matches. Returns probabilities for all fixtures in a season,
// or a single fixture if fixtureId is provided.
//
// Formula (weighted Elo-style):
//   Base:        PR rating gap            (40% weight)
//   Form:        Last 3 match results     (25% weight)
//   H2H:         Head-to-head record      (20% weight)
//   Efficiency:  Shot accuracy delta      (10% weight)
//   Defense:     Goals conceded delta     ( 5% weight)
//
// Output: winProbA (0–100), winProbB (0–100), drawProb (0–100), confidence
// Probabilities only shown when BOTH players have 4+ verified matches.
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// GET /getPlayerH2H — cross-season head-to-head record between two players
// Returns: aggregate record + per-match history across ALL seasons they've met
// Works by:
//   1. Current season matchStats with direct opponentId match
//   2. Previous seasons via linkedPreviousPlayerIds on both player docs
// ═══════════════════════════════════════════════════════════════════════════
app.get('/getPlayerH2H', async (req, res) => {
  const { myId, oppId, seasonId } = req.query;
  if (!myId || !oppId || !seasonId) return res.status(400).json({ success:false, message:'Missing myId, oppId, seasonId' });

  try {
    // Fetch both player docs to get linkedPreviousPlayerIds
    const [mySnap, oppSnap] = await Promise.all([
      db.collection('players').doc(myId).get(),
      db.collection('players').doc(oppId).get()
    ]);
    if (!mySnap.exists || !oppSnap.exists) return res.json({ success:false, message:'Player not found' });

    const myData  = mySnap.data();
    const oppData = oppSnap.data();

    // Build full ID sets including all previous season identities
    const myAllIds  = [myId,  ...(myData.linkedPreviousPlayerIds  || [])];
    const oppAllIds = [oppId, ...(oppData.linkedPreviousPlayerIds || [])];

    // Fetch all matchStats where I played vs the opponent (any identity, any season)
    // We query by my player IDs and filter by opponent IDs
    const allMatches = [];
    const batchSize = 10; // Firestore 'in' limit

    // Query in chunks if needed
    for (let i = 0; i < myAllIds.length; i += batchSize) {
      const chunk = myAllIds.slice(i, i + batchSize);
      const snap = await db.collection('matchStats')
        .where('playerId', 'in', chunk)
        .get();
      snap.forEach(doc => {
        const d = doc.data();
        // Only include if opponent is in the opponent's ID set
        if (oppAllIds.includes(d.opponentId)) {
          allMatches.push({ _id: doc.id, ...d });
        }
      });
    }

    if (!allMatches.length) {
      return res.json({ success:true, hasData:false, wins:0, draws:0, losses:0, matches:[] });
    }

    // Sort by verifiedAt descending
    allMatches.sort((a, b) => {
      const ta = a.verifiedAt ? (a.verifiedAt._seconds || 0) : 0;
      const tb = b.verifiedAt ? (b.verifiedAt._seconds || 0) : 0;
      return tb - ta;
    });

    // Calculate aggregate stats
    let wins = 0, draws = 0, losses = 0, gf = 0, ga = 0;
    const matchList = [];

    for (const m of allMatches) {
      if (m.result === 'W') wins++;
      else if (m.result === 'D') draws++;
      else losses++;
      gf += m.goalsFor   || 0;
      ga += m.goalsAgainst || 0;

      // Determine which season this match belongs to
      const matchSeasonId = m.seasonId || 'unknown';
      const isCurrent = matchSeasonId === seasonId;

      // Get date string from verifiedAt
      let dateStr = '';
      if (m.verifiedAt) {
        const ts = m.verifiedAt._seconds ? new Date(m.verifiedAt._seconds * 1000) : new Date(m.verifiedAt);
        dateStr = ts.toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' });
      }

      matchList.push({
        result:    m.result,
        goalsFor:  m.goalsFor  || 0,
        goalsAgainst: m.goalsAgainst || 0,
        matchDay:  m.matchDay  || null,
        seasonId:  matchSeasonId,
        isCurrent,
        isHome:    m.isHome,
        dateStr,
        fixtureId: m.fixtureId || null
      });
    }

    return res.json({
      success:  true,
      hasData:  true,
      wins, draws, losses,
      goalsFor: gf, goalsAgainst: ga,
      totalMatches: allMatches.length,
      currentSeasonMatches: allMatches.filter(m => m.seasonId === seasonId).length,
      prevSeasonMatches:    allMatches.filter(m => m.seasonId !== seasonId).length,
      matches: matchList
    });

  } catch(e) {
    console.error('[CEE] getPlayerH2H:', e.message);
    return res.status(500).json({ success:false, message: e.message });
  }
});

app.get('/getMatchProbabilities', async (req, res) => {
  const { seasonId, fixtureId } = req.query;
  const sid = seasonId || await getSeasonId();
  if (!sid) return res.status(400).json({ success: false, message: 'seasonId required' });

  try {
    // ── Fetch all matchStats for this season ──────────────────────────────
    const allMatchSnap = await db.collection('matchStats')
      .where('seasonId', '==', sid)
      .get();

    const playerMatchMap = {}; // playerId → [matchStat docs]
    allMatchSnap.forEach(doc => {
      const d = doc.data();
      if (!playerMatchMap[d.playerId]) playerMatchMap[d.playerId] = [];
      playerMatchMap[d.playerId].push(d);
    });

    // ── Fetch all players for PR/tier data ────────────────────────────────
    const playersSnap = await db.collection('players').get();
    const playerMap = {};
    playersSnap.forEach(doc => { playerMap[doc.id] = { id: doc.id, ...doc.data() }; });

    // ── Fetch fixtures ────────────────────────────────────────────────────
    let fixturesSnap;
    if (fixtureId) {
      const fd = await db.collection('fixtures').doc(fixtureId).get();
      fixturesSnap = fd.exists ? [fd] : [];
    } else {
      const fSnap = await db.collection('fixtures')
        .where('seasonId', '==', sid)
        .where('phase', '==', 'league')
        .get();
      fixturesSnap = fSnap.docs;
    }

    // ══════════════════════════════════════════════════════════════════════
    // PROBABILITY ENGINE v2 — Quality-Adjusted, Margin-Weighted, Decay-Form
    // ══════════════════════════════════════════════════════════════════════

    // Helper: eFootball squad strength → tier score (0-100)
    // Based on real 2026 eFootball strength tiers:
    //   3320+ = Whale ceiling (top players, full 106-108 rated squads)
    //   3250+ = Top 5-10% (Big Time / Epic Booster cards)
    //   3150  = Standard competitive average
    //   3000+ = Developing player
    //   <3000 = New/themed/authentic squad
    function _strengthScore(s) {
      if (!s || s <= 0) return 50; // no data → neutral
      if (s >= 3320) return 100;
      if (s >= 3250) return 85 + ((s - 3250) / 70) * 15;
      if (s >= 3150) return 60 + ((s - 3150) / 100) * 25;
      if (s >= 3000) return 35 + ((s - 3000) / 150) * 25;
      if (s >= 2800) return 15 + ((s - 2800) / 200) * 20;
      return 10;
    }

    // Helper: opponent quality weight based on their rank/pot
    // Win vs rank 1 player = 1.6x, win vs rank 20+ = 0.6x
    function _opponentWeight(opponentId) {
      const opp = playerMap[opponentId];
      if (!opp) return 1.0;
      const rank = opp.rank || 99;
      const pot  = opp.pot  || 4;
      // Combine rank and pot: P1 opponents top-weighted
      if (pot === 1 || rank <= 3)  return 1.6;
      if (pot === 2 || rank <= 7)  return 1.3;
      if (pot === 3 || rank <= 14) return 1.0;
      return 0.6; // P4 / bottom ranked
    }

    // Helper: score margin multiplier for a match result
    function _marginMult(goalsFor, goalsAgainst, result) {
      if (result === 'D') return 1.0;
      const margin = Math.abs((goalsFor||0) - (goalsAgainst||0));
      if (result === 'W') {
        if (margin >= 3) return 1.35;
        if (margin === 2) return 1.18;
        return 1.0;
      }
      // Loss
      if (margin >= 3) return 0.65;
      if (margin === 2) return 0.80;
      return 0.92;
    }

    function _calcProbability(pidA, pidB) {
      const matchesA = (playerMatchMap[pidA] || []).slice().sort((a,b) => {
        const ta = a.verifiedAt ? (a.verifiedAt.toMillis ? a.verifiedAt.toMillis() : new Date(a.verifiedAt).getTime()) : 0;
        const tb = b.verifiedAt ? (b.verifiedAt.toMillis ? b.verifiedAt.toMillis() : new Date(b.verifiedAt).getTime()) : 0;
        return ta - tb;
      });
      const matchesB = (playerMatchMap[pidB] || []).slice().sort((a,b) => {
        const ta = a.verifiedAt ? (a.verifiedAt.toMillis ? a.verifiedAt.toMillis() : new Date(a.verifiedAt).getTime()) : 0;
        const tb = b.verifiedAt ? (b.verifiedAt.toMillis ? b.verifiedAt.toMillis() : new Date(b.verifiedAt).getTime()) : 0;
        return ta - tb;
      });

      const pA = playerMap[pidA] || {};
      const pB = playerMap[pidB] || {};

      // ── COMPONENT 1: Squad Strength Prior ─────────────────────────────────
      // Weight decays as match data accumulates (important early season, irrelevant by MD10)
      // Arsenal 3200 vs Burnley 2850 should show significant prior advantage before kickoff
      const sA = _strengthScore(pA.strength || 0);
      const sB = _strengthScore(pB.strength || 0);
      const sTotal = sA + sB;
      const strengthProbA = sTotal > 0 ? sA / sTotal : 0.5;
      const avgMatchCount = (matchesA.length + matchesB.length) / 2;
      // Prior weight: 20% at 0 matches → 0% at 12+ matches (linear decay)
      const strengthWeight = Math.max(0, 0.20 * (1 - Math.min(avgMatchCount, 12) / 12));

      // If not enough data for statistical model, return strength-only estimate
      if (matchesA.length < 4 || matchesB.length < 4) {
        // Use strength as soft prior when available
        const hasSomeData = matchesA.length > 0 || matchesB.length > 0;
        if ((pA.strength || 0) > 0 && (pB.strength || 0) > 0) {
          const softProb = strengthProbA;
          const softWinA = Math.max(15, Math.min(80, Math.round(softProb * 85)));
          const softDraw = 15;
          const softWinB = 100 - softWinA - softDraw;
          return {
            sufficient: false,
            softEstimate: true,
            winProbA: softWinA, winProbB: Math.max(5, softWinB), drawProb: softDraw,
            reason: matchesA.length < 4
              ? `${pA.clubName || pidA} needs ${4 - matchesA.length} more match(es) for full analysis`
              : `${pB.clubName || pidB} needs ${4 - matchesB.length} more match(es) for full analysis`,
            strengthOnly: true,
            strengthA: pA.strength, strengthB: pB.strength
          };
        }
        return {
          sufficient: false,
          reason: matchesA.length < 4
            ? `${pA.clubName || pidA} needs ${4 - matchesA.length} more match(es)`
            : `${pB.clubName || pidB} needs ${4 - matchesB.length} more match(es)`
        };
      }

      // ── COMPONENT 2: Opponent-Quality-Adjusted PR (30%) ──────────────────
      // Each win/loss weighted by opponent quality so beating P1 players counts more
      const prA = pA.performanceRating != null ? pA.performanceRating : 50;
      const prB = pB.performanceRating != null ? pB.performanceRating : 50;
      // Quality-adjust: re-score PR using opponent-weighted results
      const _qualAdjPR = (matches) => {
        if (!matches.length) return 50;
        let weightedScore = 0, totalWeight = 0;
        matches.forEach(m => {
          const oppW = _opponentWeight(m.opponentId);
          const baseScore = m.result === 'W' ? 1 : m.result === 'D' ? 0.4 : 0;
          const marginM = _marginMult(m.goalsFor, m.goalsAgainst, m.result);
          weightedScore += baseScore * oppW * marginM;
          totalWeight   += oppW;
        });
        // Normalise to 0-100 PR scale
        return totalWeight > 0 ? Math.round((weightedScore / totalWeight) * 100) : 50;
      };
      const qaprA = _qualAdjPR(matchesA);
      const qaprB = _qualAdjPR(matchesB);
      const qaprDiff = qaprA - qaprB;
      const qaprProbA = 1 / (1 + Math.pow(10, -qaprDiff / 25)); // logistic: diff 25 = ~85% win

      // ── COMPONENT 3: Exponential Form Decay — last 5 matches (20%) ───────
      // Recent matches weighted heavily, margin of victory included
      // Decay: most recent = 2.0x, -2 = 1.5x, -3 = 1.0x, -4 = 0.75x, -5 = 0.5x
      const _decayFormScore = (matches) => {
        const recent = matches.slice(-5);
        const decayWeights = [0.5, 0.75, 1.0, 1.5, 2.0]; // oldest → newest
        const offset = 5 - recent.length;
        let score = 0, totalW = 0;
        recent.forEach((m, i) => {
          const dw = decayWeights[offset + i];
          const oppW = _opponentWeight(m.opponentId);
          const marginM = _marginMult(m.goalsFor, m.goalsAgainst, m.result);
          const baseScore = m.result === 'W' ? 1 : m.result === 'D' ? 0.4 : 0;
          score  += baseScore * dw * marginM * oppW;
          totalW += dw * oppW;
        });
        return totalW > 0 ? score / totalW : 0.5;
      };
      const formScoreA = _decayFormScore(matchesA);
      const formScoreB = _decayFormScore(matchesB);
      const formTotal  = formScoreA + formScoreB;
      const formProbA  = formTotal > 0 ? formScoreA / formTotal : 0.5;

      // ── COMPONENT 4: H2H with margin weighting (15%) — cross-season aware ──
      // Current season: direct opponentId match
      const h2hMatchesA = matchesA.filter(m => m.opponentId === pidB);
      const h2hMatchesB = matchesB.filter(m => m.opponentId === pidA);

      // Previous seasons: look up via linkedPreviousPlayerIds on both player docs
      const prevIdsA = (pA.linkedPreviousPlayerIds || []);
      const prevIdsB = (pB.linkedPreviousPlayerIds || []);
      // matchesA where opponentId is any of B's previous IDs (= prev season meetings)
      const prevH2hA = prevIdsB.length
        ? matchesA.filter(m => prevIdsB.includes(m.opponentId))
        : [];
      const prevH2hB = prevIdsA.length
        ? matchesB.filter(m => prevIdsA.includes(m.opponentId))
        : [];
      // Also check B's previous IDs against A's previous matches
      const allH2hA = [...h2hMatchesA, ...prevH2hA];
      const allH2hB = [...h2hMatchesB, ...prevH2hB];

      let h2hProbA = 0.5;
      const hasH2H = allH2hA.length > 0 || allH2hB.length > 0;
      if (hasH2H) {
        let h2hScoreA = 0, h2hScoreB = 0, h2hTotalW = 0;
        allH2hA.forEach(m => {
          // Previous season matches weighted at 60% to reflect recency
          const seasMult = prevH2hA.includes(m) ? 0.6 : 1.0;
          const marginM  = _marginMult(m.goalsFor, m.goalsAgainst, m.result);
          const baseScore = m.result === 'W' ? 1 : m.result === 'D' ? 0.4 : 0;
          h2hScoreA += baseScore * marginM * seasMult;
          h2hTotalW += marginM * seasMult;
        });
        allH2hB.forEach(m => {
          const seasMult = prevH2hB.includes(m) ? 0.6 : 1.0;
          const marginM  = _marginMult(m.goalsFor, m.goalsAgainst, m.result);
          const baseScore = m.result === 'W' ? 1 : m.result === 'D' ? 0.4 : 0;
          h2hScoreB += baseScore * marginM * seasMult;
          h2hTotalW += marginM * seasMult;
        });
        if (h2hTotalW > 0) {
          h2hProbA = h2hScoreA / (h2hScoreA + h2hScoreB + 0.001);
        }
      }
      const h2hWeight = hasH2H ? 0.15 : 0;
      // Build H2H record string for response (cross-season)
      const h2hWinsA = allH2hA.filter(m => m.result === 'W').length;
      const h2hDrawsA = allH2hA.filter(m => m.result === 'D').length;
      const h2hLossesA = allH2hA.filter(m => m.result === 'L').length;
      const prevMeetings = prevH2hA.length + prevH2hB.length;

      // ── COMPONENT 5: Possession + Shot quality control score (10%) ───────
      // High possession + clinical shooting = controlled dominance
      const _controlScore = (matches) => {
        const posVals  = matches.map(m => m.stats?.possession != null ? m.stats.possession / 100 : null).filter(v => v !== null);
        const shotVals = matches.map(m => m.stats?.shots > 0 && m.stats?.shotsOnTarget != null ? m.stats.shotsOnTarget / m.stats.shots : null).filter(v => v !== null);
        const avgPos  = posVals.length  ? posVals.reduce((a,b)  => a+b,0) / posVals.length  : 0.5;
        const avgShot = shotVals.length ? shotVals.reduce((a,b) => a+b,0) / shotVals.length : 0.4;
        // Combined: 60% possession, 40% shot quality
        return avgPos * 0.6 + avgShot * 0.4;
      };
      const ctrlA = _controlScore(matchesA);
      const ctrlB = _controlScore(matchesB);
      const ctrlTotal = ctrlA + ctrlB;
      const ctrlProbA = ctrlTotal > 0 ? ctrlA / ctrlTotal : 0.5;

      // ── COMPONENT 6: Defensive solidity (5%) ─────────────────────────────
      // Goals conceded + defensive activity (tackles + interceptions)
      const _defScore = (matches) => {
        const gaVals = matches.map(m => m.goalsAgainst != null ? m.goalsAgainst : null).filter(v => v !== null);
        const actVals = matches.map(m => {
          const t = m.stats?.tackles ?? null;
          const i = m.stats?.interceptions ?? null;
          if (t === null && i === null) return null;
          return Math.min(1.0, ((t||0) + (i||0)) / 12); // normalise: 12 combined = max
        }).filter(v => v !== null);
        const avgGA  = gaVals.length  ? gaVals.reduce((a,b)  => a+b,0) / gaVals.length  : 1.5;
        const avgAct = actVals.length ? actVals.reduce((a,b) => a+b,0) / actVals.length : 0.4;
        // Lower GA = better. Higher activity = better.
        const gaScore  = Math.max(0, Math.min(1, 1 - avgGA / 4));
        return gaScore * 0.65 + avgAct * 0.35;
      };
      const defScoreA = _defScore(matchesA);
      const defScoreB = _defScore(matchesB);
      const defTotal  = defScoreA + defScoreB;
      const defProbA  = defTotal > 0 ? defScoreA / defTotal : 0.5;

      // ── Dynamic weight allocation ─────────────────────────────────────────
      // Weights sum to 1.0. H2H weight redistributed to QAPR+Form if no H2H.
      const baseWeights = {
        strength: strengthWeight,        // 0-20% (decays with match count)
        qapr:     0.30,
        form:     0.20,
        h2h:      h2hWeight,            // 0 or 0.15
        ctrl:     0.10,
        def:      0.05
      };
      // Remaining after strength + h2h deductions
      const fixedSum = baseWeights.strength + baseWeights.h2h + baseWeights.ctrl + baseWeights.def;
      const qaprFormBudget = 1.0 - fixedSum;
      // Split remaining 60/40 between qapr and form
      const wQAPR = qaprFormBudget * 0.60;
      const wForm = qaprFormBudget * 0.40;

      const rawProbA = (
        strengthProbA * baseWeights.strength +
        qaprProbA     * wQAPR                +
        formProbA     * wForm                +
        h2hProbA      * baseWeights.h2h      +
        ctrlProbA     * baseWeights.ctrl     +
        defProbA      * baseWeights.def
      );

      // ── Draw probability ───────────────────────────────────────────────────
      const closeness  = 1 - Math.abs(rawProbA - 0.5) * 2;
      const drawProb   = Math.round(closeness * 20); // max 20% (eFootball tends decisive)
      const winProbARaw = Math.round(rawProbA * (100 - drawProb));
      const winProbBRaw = 100 - drawProb - winProbARaw;
      const winProbA   = Math.max(5, Math.min(88, winProbARaw));
      const winProbB   = Math.max(5, Math.min(88, winProbBRaw));
      const drawProbFinal = 100 - winProbA - winProbB;

      // ── Confidence score ───────────────────────────────────────────────────
      const avgMatches2 = (matchesA.length + matchesB.length) / 2;
      const confidence  = Math.min(100, Math.round(
        (Math.min(avgMatches2, 12) / 12) * 60 +  // up to 60% from match volume
        (hasH2H ? 20 : 0)                       +  // 20% from H2H data
        ((pA.strength && pB.strength) ? 10 : 0)  + // 10% if strength data exists
        10                                          // base 10%
      ));

      // ── Narrative ─────────────────────────────────────────────────────────
      let narrative = '';
      if (winProbA >= 72)      narrative = `${pA.clubName || 'Team A'} are strong favourites`;
      else if (winProbA >= 60) narrative = `${pA.clubName || 'Team A'} have the edge`;
      else if (winProbA >= 48) narrative = 'Evenly matched — could go either way';
      else if (winProbB >= 60) narrative = `${pB.clubName || 'Team B'} have the edge`;
      else                     narrative = `${pB.clubName || 'Team B'} are strong favourites`;

      // ── Recent form strings (for display) ────────────────────────────────
      const recentA = matchesA.slice(-5);
      const recentB = matchesB.slice(-5);

      return {
        sufficient:    true,
        winProbA, winProbB, drawProb: drawProbFinal,
        confidence,
        narrative,
        prA: qaprA, prB: qaprB,          // now quality-adjusted
        strengthA: pA.strength || 0,
        strengthB: pB.strength || 0,
        tierA: pA.playerTier || null,
        tierB: pB.playerTier || null,
        formA: recentA.map(m => m.result).join(''),
        formB: recentB.map(m => m.result).join(''),
        h2hRecord: hasH2H
          ? `${h2hWinsA}W-${h2hDrawsA}D-${h2hLossesA}L`
            + (prevMeetings > 0 ? ` (incl. ${prevMeetings} prev season)` : '')
          : 'No H2H',
        // Expose component breakdown for transparency
        components: {
          strengthPrior: Math.round(strengthProbA * 100),
          qualAdjPR:     Math.round(qaprProbA * 100),
          decayForm:     Math.round(formProbA * 100),
          h2h:           Math.round(h2hProbA * 100),
          control:       Math.round(ctrlProbA * 100),
          defense:       Math.round(defProbA * 100)
        }
      };
    }

    // ── Helper: AI tactical insight for a matchup ────────────────────────
    // Reads playstyle fingerprints and returns contextual analysis
    async function _aiTacticalInsight(pidA, pidB, prob) {
      if (!prob.sufficient) return null;
      try {
        const [fpASnap, fpBSnap] = await Promise.all([
          db.collection('playerProfile').doc(pidA).get(),
          db.collection('playerProfile').doc(pidB).get()
        ]);
        const fpA = fpASnap.exists ? fpASnap.data() : null;
        const fpB = fpBSnap.exists ? fpBSnap.data() : null;
        const pA  = playerMap[pidA] || {};
        const pB  = playerMap[pidB] || {};

        // Only call AI if at least one fingerprint exists
        if (!fpA && !fpB) return null;

        const prompt = `You are a tactical analyst for Campus eSports Elite, a university eFootball tournament. Analyse this upcoming fixture and provide a concise tactical breakdown.

FIXTURE:
${pA.clubName || 'Team A'} (Strength: ${pA.strength || 'unknown'}, Pot: P${pA.pot || '?'}) vs ${pB.clubName || 'Team B'} (Strength: ${pB.strength || 'unknown'}, Pot: P${pB.pot || '?'})

STATISTICAL PROBABILITY:
${pA.clubName || 'Team A'}: ${prob.winProbA}% | Draw: ${prob.drawProb}% | ${pB.clubName || 'Team B'}: ${prob.winProbB}%
Confidence: ${prob.confidence}%

${fpA ? `${pA.clubName || 'Team A'} PLAYSTYLE:
${fpA.fingerprintText || 'No fingerprint data'}` : `${pA.clubName || 'Team A'}: No behavioural data yet`}

${fpB ? `${pB.clubName || 'Team B'} PLAYSTYLE:
${fpB.fingerprintText || 'No fingerprint data'}` : `${pB.clubName || 'Team B'}: No behavioural data yet`}

Respond ONLY in JSON, no markdown, no preamble:
{
  "keyBattleground": "<one sentence: the specific tactical contest that will decide this match>",
  "upsetPath": "<one sentence: exactly how the underdog can win>",
  "tacticalEdge": "<one sentence: what the favourite must do to guarantee the win>",
  "watchFor": "<one word or short phrase: the key stat or moment to watch>"
}`;

        const gaRes = await _geminiPost({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { maxOutputTokens: 300, temperature: 0.3 }
        });
        if (!gaRes.ok) return null;
        const raw = (gaRes.data?.candidates?.[0]?.content?.parts?.[0]?.text || '').trim();
        const clean = raw.replace(/```json|```/g, '').trim();
        return JSON.parse(clean);
      } catch(e) {
        console.warn('[CEE] AI tactical insight failed (non-blocking):', e.message);
        return null;
      }
    }

    // ── Calculate for all fixtures ────────────────────────────────────────
    const results = [];
    let aiInsightCount = 0; // cap AI calls to protect Gemini quota
    for (const doc of fixturesSnap) {
      const f   = doc.data ? doc.data() : doc;
      const fid = doc.id;
      const pidA = f.playerAId;
      const pidB = f.playerBId;
      if (!pidA || !pidB) continue;

      const prob = _calcProbability(pidA, pidB);

      // AI tactical insight — only for PENDING upcoming fixtures with sufficient data
      // Cap at 10 calls per request to protect Gemini quota
      let tacticalInsight = null;
      const isPending = !f.status || f.status === 'pending' || f.status === 'open';
      if (prob.sufficient && isPending && aiInsightCount < 10) {
        aiInsightCount++;
        tacticalInsight = await _aiTacticalInsight(pidA, pidB, prob).catch(() => null);
      }

      results.push({
        fixtureId: fid,
        playerAId: pidA,
        playerBId: pidB,
        playerAName: playerMap[pidA]?.clubName || pidA,
        playerBName: playerMap[pidB]?.clubName || pidB,
        matchDay: f.matchday || null,
        status: f.status || null,
        ...prob,
        tacticalInsight
      });
    }

    // ── Cache full season probabilities to Firestore ──────────────────────
    if (!fixtureId) {
      db.collection('config').doc('matchProbabilities').set({
        seasonId: sid,
        probabilities: results,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }).catch(e => console.error('[CEE] prob cache write failed:', e.message));
    }

    return res.json({ success: true, seasonId: sid, probabilities: results });
  } catch(e) {
    console.error('[CEE] getMatchProbabilities error:', e.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET /getScoutReport — returns cached scout report if available
// ═══════════════════════════════════════════════════════════════════════════
app.get('/getScoutReport', async (req, res) => {
  const { requestingPlayerId, opponentPlayerId, seasonId } = req.query;
  if (!requestingPlayerId || !opponentPlayerId || !seasonId) {
    return res.status(400).json({ success: false, message: 'Missing fields.' });
  }
  try {
    const reportDocId = `${requestingPlayerId}_${opponentPlayerId}_${seasonId}`;
    const snap = await db.collection('scoutReports').doc(reportDocId).get();
    if (!snap.exists) return res.json({ success: false, reason: 'no_cache', message: 'No report generated yet.' });
    const r = snap.data();
    // Check if opponent has played new matches since last generation
    const latestOppSnap = await db.collection('matchStats')
      .where('playerId', '==', opponentPlayerId)
      .where('seasonId', '==', seasonId)
      .orderBy('verifiedAt', 'desc')
      .limit(1)
      .get();
    let isStale = false;
    if (!latestOppSnap.empty) {
      const latestId = latestOppSnap.docs[0].id;
      isStale = r.opponentLastMatchId !== latestId;
    }
    return res.json({
      success: true,
      cached: true,
      isStale,
      reportText: r.reportText,
      upgradeText: r.upgradeText || '',
      matchesAnalysed: r.matchesAnalysed,
      opponentName: r.opponentName || null,
      generatedAt: r.generatedAt ? r.generatedAt.toDate().toISOString() : null
    });
  } catch(e) {
    return res.status(500).json({ success: false, message: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// POST /approveResult — Admin approves a match result
// Marks fixture approved, notifies both players, triggers standings recalc.
// Called from admin Result Queue and arbitration panel in frontend.
// ═══════════════════════════════════════════════════════════════════════════
app.post('/approveResult', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  const { fixtureId } = req.body;
  if (!fixtureId) return res.status(400).json({ success: false, message: 'Missing fixtureId' });
  try {
    const fixRef  = db.collection('fixtures').doc(fixtureId);
    const fixSnap = await fixRef.get();
    if (!fixSnap.exists) return res.json({ success: false, message: 'Fixture not found' });
    const fix = fixSnap.data();

    // Extract score from whichever submission exists
    const hg = fix.playerAGoals ?? fix.aiExtractedA?.home ?? null;
    const ag = fix.playerBGoals ?? fix.aiExtractedA?.away ?? null;

    // Mark approved
    await fixRef.update({
      status: 'approved',
      adminApproved: true,
      done: true,
      adminApprovedAt: admin.firestore.FieldValue.serverTimestamp(),
      playerAGoals: hg,
      playerBGoals: ag
    });

    // Notify both players
    const seasonId = fix.seasonId || await getSeasonId();
    await _sendMatchNotifications('RESULT_APPROVED', fixtureId, fix.playerAId, fix.playerBId, seasonId);

    // Recalculate standings
    if (seasonId) {
      _recalcStandingsInternal(seasonId).catch(e =>
        console.error('[CEE] approveResult standings error:', e.message)
      );
    }

    await audit('ADMIN_APPROVE_RESULT', fixtureId, 'fixture',
      `Admin manually approved result: ${hg ?? '?'}-${ag ?? '?'}`);

    return res.json({ success: true, message: 'Result approved. Players notified.' });
  } catch(e) {
    console.error('[CEE] approveResult error:', e.message);
    return res.status(500).json({ success: false, message: e.message });
  }
});

// POST /adminSetIntelligenceConfig — admin enable/disable switch
// ═══════════════════════════════════════════════════════════════════════════
app.post('/adminSetIntelligenceConfig', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  const { analysisEnabled } = req.body;
  if (typeof analysisEnabled !== 'boolean') return res.status(400).json({ success: false, message: 'analysisEnabled must be boolean.' });
  try {
    await db.collection('config').doc('intelligence').set({ analysisEnabled }, { merge: true });
    await audit('INTELLIGENCE_CONFIG', 'config', 'intelligence', `analysisEnabled set to ${analysisEnabled}`);
    return res.json({ success: true });
  } catch(e) { return res.status(500).json({ success: false, message: e.message }); }
});

// GET /adminGetIntelligenceConfig — returns current intelligence config + stats
app.get('/adminGetIntelligenceConfig', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  try {
    const doc = await db.collection('config').doc('intelligence').get();
    const data = doc.exists ? doc.data() : {};
    const reportsSnap = await db.collection('scoutReports').get();
    return res.json({ success: true, analysisEnabled: data.analysisEnabled !== false, reportsGenerated: reportsSnap.size, lastGeminiCallAt: data.lastGeminiCallAt ? data.lastGeminiCallAt.toDate().toISOString() : null, reportsGeneratedTotal: data.reportsGeneratedTotal || 0 });
  } catch(e) { return res.status(500).json({ success: false, message: e.message }); }
});



// ═══════════════════════════════════════════════════════════════════════════
// POST /requestPinReset — self-service PIN reset (₦150 via Paystack)
// Body: { tag, email, paystackRef, seasonId }
// ═══════════════════════════════════════════════════════════════════════════
app.post('/requestPinReset', async (req, res) => {
  const { tag, email, paystackRef, seasonId } = req.body;
  if (!tag||!email||!paystackRef||!seasonId)
    return res.status(400).json({ success:false, message:'Missing fields.' });
  try {
    const tagUpper = tag.toUpperCase().trim();
    const emailLow = email.toLowerCase().trim();
    // Find player by tag
    let player = null;
    const snaps = await Promise.all([
      db.collection('players').where('seasonId','==',seasonId).where('gameName','==',tagUpper).limit(1).get(),
      db.collection('players').where('seasonId','==',seasonId).where('clubName','==',tagUpper).limit(1).get(),
      db.collection('players').where('seasonId','==',seasonId).where('initials','==',tagUpper).limit(1).get(),
    ]);
    for (const s of snaps) { if (!s.empty) { const d=s.docs[0]; player={id:d.id,...d.data()}; break; } }
    if (!player) return res.json({ success:false, message:'Player not found. Check your gaming tag.' });
    // Verify email matches
    if ((player.email||'').toLowerCase().trim() !== emailLow)
      return res.json({ success:false, message:'Email does not match our records for this tag.' });
    // Verify Paystack payment
    const psSecret = process.env.PAYSTACK_SECRET;
    if (psSecret && !psSecret.startsWith('sk_test') && paystackRef !== 'BYPASS') {
      const psVerify = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(paystackRef)}`,
        { headers:{ Authorization:`Bearer ${psSecret}` } });
      const psData = await psVerify.json();
      if (!psData.status || psData.data.status !== 'success')
        return res.json({ success:false, message:'Payment verification failed. Please try again.' });
      if (psData.data.amount < 15000)
        return res.json({ success:false, message:'Payment amount incorrect. PIN reset requires ₦150.' });
    }
    // Generate new PIN
    const newPin = String(Math.floor(1000+Math.random()*9000));
    const newHash = await bcrypt.hash(newPin, 12);
    // Clear lockout and block, set new PIN
    await db.collection('playerSecrets').doc(player.id).update({
      pinHash: newHash,
      pinFailAttempts: 0,
      pinLockoutUntil: null,
      pinPermanentBlock: false,
      pinLockoutCount: 0,
      pinResetAt: admin.firestore.FieldValue.serverTimestamp(),
      pinResetRef: paystackRef
    });
    // Notify player via email + Telegram
    if (player.email) {
      sendEmail(player.email, 'CEE — Your New PIN 🔐',
        `<p>Your PIN has been reset successfully.</p>
         <div class="hl" style="font-size:36px;font-weight:700;letter-spacing:.5em;text-align:center">${newPin}</div>
         <p><strong>Keep this PIN safe.</strong> Use it to access the CEE Player Hub.</p>`).catch(()=>{});
    }
    if (player.telegramChatId) {
      sendTelegram(player.telegramChatId,
        `🔐 <b>PIN Reset Successful</b>\n\nYour new PIN is: <b>${newPin}</b>\n\nKeep this private. Use it to access the CEE Player Hub.`
      ).catch(()=>{});
    }
    await audit('PIN_RESET_PAID', player.id, 'player', `PIN reset via ₦150 payment. Ref: ${paystackRef}`);
    return res.json({ success:true, message:'PIN reset successful. Check your email and Telegram for your new PIN.' });
  } catch(e) {
    console.error('[CEE] requestPinReset error:', e.message);
    return res.status(500).json({ success:false, message:e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /unlockPinAccount — unlock permanently blocked account (₦300 via Paystack)
// Body: { playerId, paystackRef }
// ═══════════════════════════════════════════════════════════════════════════
app.post('/unlockPinAccount', async (req, res) => {
  const { playerId, paystackRef } = req.body;
  if (!playerId||!paystackRef)
    return res.status(400).json({ success:false, message:'Missing fields.' });
  try {
    const psSecret = process.env.PAYSTACK_SECRET;
    if (psSecret && !psSecret.startsWith('sk_test') && paystackRef !== 'BYPASS') {
      const psVerify = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(paystackRef)}`,
        { headers:{ Authorization:`Bearer ${psSecret}` } });
      const psData = await psVerify.json();
      if (!psData.status || psData.data.status !== 'success')
        return res.json({ success:false, message:'Payment verification failed.' });
      if (psData.data.amount < 30000)
        return res.json({ success:false, message:'Payment amount incorrect. Unlock requires ₦300.' });
    }
    const pdSnap = await db.collection('players').doc(String(playerId)).get();
    if (!pdSnap.exists) return res.json({ success:false, message:'Player not found.' });
    const player = pdSnap.data();
    // Generate new PIN and unlock
    const newPin = String(Math.floor(1000+Math.random()*9000));
    const newHash = await bcrypt.hash(newPin, 12);
    await db.collection('playerSecrets').doc(String(playerId)).update({
      pinHash: newHash,
      pinFailAttempts: 0,
      pinLockoutUntil: null,
      pinPermanentBlock: false,
      pinLockoutCount: 0,
      pinUnlockedAt: admin.firestore.FieldValue.serverTimestamp(),
      pinUnlockRef: paystackRef
    });
    if (player.email) {
      sendEmail(player.email, 'CEE — Account Unlocked 🔓',
        `<p>Your account has been unlocked. Your new PIN is:</p>
         <div class="hl" style="font-size:36px;font-weight:700;letter-spacing:.5em;text-align:center">${newPin}</div>
         <p>Keep this private. This is your final warning — further repeated failures may result in a permanent ban.</p>`).catch(()=>{});
    }
    if (player.telegramChatId) {
      sendTelegram(player.telegramChatId,
        `🔓 <b>Account Unlocked</b>\n\nYour new PIN is: <b>${newPin}</b>\n\nThis is your final warning.`
      ).catch(()=>{});
    }
    const adminChat = env.telegram && env.telegram.admin_chat_id;
    if (adminChat) sendTelegram(adminChat,
      `🔓 Account unlocked\nPlayer: ${player.clubName||player.gameName}\nPaid ₦300. Ref: ${paystackRef}`
    ).catch(()=>{});
    await audit('PIN_UNLOCK_PAID', playerId, 'player', `Account unlocked via ₦300 payment. Ref: ${paystackRef}`);
    return res.json({ success:true, message:'Account unlocked. Check your email and Telegram for your new PIN.' });
  } catch(e) {
    console.error('[CEE] unlockPinAccount error:', e.message);
    return res.status(500).json({ success:false, message:e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GET /getAutomationConfig — returns all automation toggle states
// ═══════════════════════════════════════════════════════════════════════════
app.get('/getAutomationConfig', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  try {
    const doc = await db.collection('config').doc('automation').get();
    const d = doc.exists ? doc.data() : {};
    return res.json({ success:true,
      masterEnabled:         d.masterEnabled         !== false,
      autoLaunch:            d.autoLaunch            !== false,
      autoApproveReg:        d.autoApproveReg        !== false,
      autoPotAssign:         d.autoPotAssign         !== false,
      autoOpenWindows:       d.autoOpenWindows       !== false,
      autoSeasonNotify:      d.autoSeasonNotify      !== false,
      potThresholds:         d.potThresholds         || { p1:3250, p2:3150, p3:3000 }
    });
  } catch(e) { return res.status(500).json({ success:false, message:e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /setAutomationConfig — save automation toggle states
// ═══════════════════════════════════════════════════════════════════════════
app.post('/setAutomationConfig', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  try {
    const allowed = ['masterEnabled','autoLaunch','autoApproveReg','autoPotAssign','autoOpenWindows','autoSeasonNotify','potThresholds'];
    const update = {};
    for (const k of allowed) { if (req.body[k] !== undefined) update[k] = req.body[k]; }
    await db.collection('config').doc('automation').set(update, { merge:true });
    await audit('AUTOMATION_CONFIG', 'config', 'automation', JSON.stringify(update));
    return res.json({ success:true });
  } catch(e) { return res.status(500).json({ success:false, message:e.message }); }
});

app.post('/testAiVerify', async (req, res) => {
  if (!assertAdminSecret(req, res)) return;
  const { screenshotBase64, mimeType } = req.body;
  if (!screenshotBase64) return res.status(400).json({ success: false, message: 'Missing screenshotBase64' });
  try {
    const _gr3 = await _geminiPost({
        contents: [{ parts: [
          { inline_data: { mime_type: mimeType || 'image/jpeg', data: screenshotBase64 } },
          { text: 'You are the CEE Anti-Cheat Vision System. Analyse this screenshot for fraud and extract stats.\n\nPART 1 — FRAUD DETECTION:\nExamine for signs of image editing, statistical impossibilities, UI inconsistencies, and score implausibility. Reason from what you see.\n\nPART 2 — STAT EXTRACTION:\nExtract every number precisely.\n\nRespond ONLY in JSON with no markdown:\n{\n  "isEfootballResultScreen": true/false,\n  "isFullResultScreen": true/false,\n  "homeGoals": <integer or null>,\n  "awayGoals": <integer or null>,\n  "homeClubName": "<string or null>",\n  "awayClubName": "<string or null>",\n  "isPlausibleScore": true/false,\n  "confidence": <float 0.0-1.0>,\n  "fraudSuspicion": <float 0.0-1.0>,\n  "fraudIndicators": [<specific suspicious observations, empty if none>],\n  "statAnomalies": [<mathematically inconsistent stats, empty if none>],\n  "readingIssues": [<parts that were hard to read, empty if none>],\n  "uiAuthenticityScore": <float 0.0-1.0>,\n  "imageQualityScore": <float 0.0-1.0>\n}\nRules:\n- fraudSuspicion: 0.0=definitely real, 1.0=definitely fake. Be precise.\n- fraudIndicators: list every visual/structural anomaly you detect.\n- uiAuthenticityScore: how closely this matches a genuine eFootball post-match stats screen.\n- isPlausibleScore: false if goal difference >= 8 or either score > 15.\n- confidence: certainty all values were read correctly.' }
        ]}],
        generationConfig: { maxOutputTokens:8000, temperature: 0 }
      });
    if (!_gr3.ok) throw new Error(_gr3.error || 'Gemini Vision call failed');
    const rawText = (_gr3.data.candidates&&_gr3.data.candidates[0]&&_gr3.data.candidates[0].content&&_gr3.data.candidates[0].content.parts&&_gr3.data.candidates[0].content.parts[0]&&_gr3.data.candidates[0].content.parts[0].text) || '';
    if (!rawText || !rawText.trim()) {
      return res.json({ success: false, message: 'Gemini returned empty response — your API key may have hit quota. Check Railway logs.' });
    }
    let ai;
    const cleanedText = rawText.replace(/```json|```/g,'').trim();
    if (!cleanedText) {
      return res.json({ success: false, message: 'Gemini returned a response but no JSON content — quota may be hit or image was blocked by safety filters. Check Railway logs.' });
    }
    try { ai = JSON.parse(cleanedText); }
    catch(pe) { return res.json({ success: false, message: 'Gemini response parse error: ' + pe.message + ' | Raw: ' + rawText.substring(0,80) }); }
    const conf = ai.confidence || 0;
    const detectedA = ai.homeGoals !== null && ai.homeGoals !== undefined ? ai.homeGoals : '?';
    const detectedB = ai.awayGoals !== null && ai.awayGoals !== undefined ? ai.awayGoals : '?';
    const imgQuality = ai.imageQualityScore || ai.uiMatchScore || conf;
    const aiApproved = ai.isEfootballResultScreen && ai.isFullResultScreen && conf >= 0.85;
    const fraudSusp   = ai.fraudSuspicion != null ? ai.fraudSuspicion : 0;
    const uiAuth      = ai.uiAuthenticityScore != null ? ai.uiAuthenticityScore : 1.0;
    const fraudInds   = Array.isArray(ai.fraudIndicators) ? ai.fraudIndicators : [];
    const statAnoms   = Array.isArray(ai.statAnomalies)   ? ai.statAnomalies   : [];
    const readIssues  = Array.isArray(ai.readingIssues)   ? ai.readingIssues   : [];
    return res.json({
      success: true,
      aiApproved,
      confidence: conf,
      detectedScore: `${detectedA} - ${detectedB}`,
      fraudSuspicion:       fraudSusp,
      fraudIndicators:      fraudInds,
      statAnomalies:        statAnoms,
      readingIssues:        readIssues,
      uiAuthenticityScore:  uiAuth,
      imageQualityScore:    ai.imageQualityScore || conf,
      isEfootballResultScreen: ai.isEfootballResultScreen,
      isFullResultScreen:      ai.isFullResultScreen,
      homeClubName: ai.homeClubName,
      awayClubName: ai.awayClubName,
      aiNotes: !ai.isEfootballResultScreen ? 'Not an eFootball result screen' : conf >= 0.85 ? 'Screenshot read successfully' : 'Low confidence — try a clearer screenshot'
    });
  } catch(e) {
    console.error('[CEE] testAiVerify error:', e.message);
    return res.json({ success: false, message: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[CEE] ✅ Backend running on port ${PORT}`);
  console.log(`[CEE] URL: https://campus-esports-elite-backend2-production.up.railway.app`);
  // Load tokens from Firestore adminSettings (bridges admin UI → backend runtime)
  // This allows admin to save TELEGRAM_TOKEN + Brevo keys via the Season Clock UI
  // without needing to set Railway env vars manually
  _loadTokensFromFirestore().then(() => {
    // Re-run env check after Firestore token load
    const tgOk = !!(env.telegram && env.telegram.token);
    const brevoOk = _brevoAccounts.length > 0;
    if (tgOk)    console.log('[CEE] ✅ Telegram: token configured and ready');
    else         console.warn('[CEE] ⚠️  Telegram: no token — set TELEGRAM_TOKEN in Railway or save via Season Clock → API Keys');
    if (brevoOk) console.log(`[CEE] ✅ Brevo: ${_brevoAccounts.length} account(s) ready — ${_brevoAccounts.length * 295} emails/day`);
    else         console.warn('[CEE] ⚠️  Brevo: no accounts — set BREVO_KEY_1+BREVO_FROM_1 in Railway or save via Season Clock → API Keys');
  }).catch(() => {});
  // Startup env check — show what's configured and what's missing
  const checks = {
    'FIREBASE_SERVICE_ACCOUNT': !!(serviceAccount && serviceAccount.project_id),
    'FIREBASE_STORAGE_BUCKET':  !!process.env.FIREBASE_STORAGE_BUCKET,
    'BREVO_KEY_1':              !!process.env.BREVO_KEY_1,
    'BREVO_FROM_1':             !!process.env.BREVO_FROM_1,
    'TELEGRAM_TOKEN':           !!process.env.TELEGRAM_TOKEN,
    'TELEGRAM_ADMIN_CHAT_ID':   !!process.env.TELEGRAM_ADMIN_CHAT_ID,
    'ADMIN_SECRET':             !!process.env.ADMIN_SECRET,
    'ADMIN_EMAIL':              !!process.env.ADMIN_EMAIL,
    'PAYSTACK_SECRET':          !!process.env.PAYSTACK_SECRET,
    'GEMINI_KEY_1':             !!_geminiKeys.length,
    'VAPID_PUBLIC_KEY':         !!process.env.VAPID_PUBLIC_KEY,
    'VAPID_PRIVATE_KEY':        !!process.env.VAPID_PRIVATE_KEY,
  };
  const ok  = Object.entries(checks).filter(([,v]) => v).map(([k]) => k);
  const bad = Object.entries(checks).filter(([,v]) => !v).map(([k]) => k);
  if (ok.length)  console.log('[CEE] ✅ Env OK:      ', ok.join(', '));
  if (bad.length) console.log('[CEE] ❌ Env MISSING: ', bad.join(', '));
  if (serviceAccount && !serviceAccount.project_id) {
    console.error('[CEE] ⚠️  FIREBASE_SERVICE_ACCOUNT parsed but has no project_id — check it is the full service account JSON, not a partial value.');
  }
  console.log('[CEE] Scheduled jobs active: windowManager(15m), submissionDeadlineEnforcer(10m),');
  console.log('[CEE]   autoApprover(5m), disputeAutoResolver(30m), doubleConsentExpiryEnforcer(30m),');
  console.log('[CEE]   swissPairingEngine(6h), registrationDeadlineChecker(daily),');
  console.log('[CEE]   dailyAdminDigest(08:00 WAT), replayAutoScheduler(06:00 WAT),');
  console.log('[CEE]   notificationRetryWorker(2h)');
  console.log('[CEE] Firestore listeners: fixtures, registrations');
});
