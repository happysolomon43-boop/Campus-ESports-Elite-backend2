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
 *   GEMINI_KEY                 Google AI Studio key (free, gemini-2.0-flash)
 *   GMAIL_USER                 Gmail address for SMTP
 *   GMAIL_PASS                 Gmail App Password
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
const nodemailer   = require('nodemailer');
const crypto       = require('crypto');
const bcrypt       = require('bcrypt');
const fetch        = require('node-fetch');

// ── Firebase Admin init ───────────────────────────────────────────────────
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
admin.initializeApp({
  credential:    admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET || ''
});
const db      = admin.firestore();
const storage = admin.storage();

// ── Environment config (replaces functions.config()) ─────────────────────
const env = {
  gemini:   { key:           process.env.GEMINI_KEY },
  gmail:    { user:          process.env.GMAIL_USER,
              pass:          process.env.GMAIL_PASS },
  telegram: { token:         process.env.TELEGRAM_TOKEN,
              admin_chat_id: process.env.TELEGRAM_ADMIN_CHAT_ID },
  admin:    { email:         process.env.ADMIN_EMAIL,
              player_id:     process.env.ADMIN_PLAYER_ID,
              secret:        process.env.ADMIN_SECRET },
  paystack: { secret:        process.env.PAYSTACK_SECRET }
};

// ── Startup config validation ─────────────────────────────────────────────
(function _validateConfig() {
  const required = ['GEMINI_KEY','GMAIL_USER','GMAIL_PASS','TELEGRAM_TOKEN',
                    'TELEGRAM_ADMIN_CHAT_ID','ADMIN_EMAIL','ADMIN_SECRET'];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length > 0) {
    console.error(`[CEE] FATAL: Missing env vars: ${missing.join(', ')}`);
    console.error('[CEE] Set them in Railway → Variables before deploying.');
  }
})();

// ── Express app ───────────────────────────────────────────────────────────
const app = express();
app.use(corsMidd({
  origin: '*',
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','x-cee-admin-secret']
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
  if (!secret || provided !== secret) {
    res.status(403).json({ success: false, message: 'Forbidden' });
    return false;
  }
  return true;
}

// ── Nodemailer transporter (lazy-init) ────────────────────────────────────
let _transporter = null;
function getTransporter() {
  if (!_transporter) {
    _transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: env.gmail.user, pass: env.gmail.pass }
    });
  }
  return _transporter;
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

// ── sendEmail wrapper ─────────────────────────────────────────────────────
async function sendEmail(to, subject, htmlBody, textBody) {
  try {
    const info = await getTransporter().sendMail({
      from: `"CEE League" <${env.gmail.user}>`, to, subject,
      html: emailHtml(subject, htmlBody), text: textBody || subject
    });
    return { success: true, messageId: info.messageId };
  } catch (e) {
    console.error('[CEE] Email error:', e.message);
    return { success: false, error: e.message };
  }
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
async function _notifyBothReady(fix, fixtureId) {
  const msg  = `⚡ <b>BOTH PLAYERS READY!</b>\n\nYour match is now <b>IN PROGRESS</b>.\nPlay your game and submit your result screenshot via the Player Hub.\n\n<b>Deadline:</b> 5 hours from now (or 1 hour before window closes).`;
  const html = `<p>⚡ Both you and your opponent have clicked Ready!</p>
    <p>Your match is now <strong>IN PROGRESS</strong>. Play your game and submit your result screenshot from the Player Hub.</p>
    <div class="hl">Submission deadline: 5 hours from now (or 1 hour before the window closes)</div>`;
  const promises = [];
  for (const pid of [fix.playerAId, fix.playerBId].filter(Boolean)) {
    const p = await db.collection('players').doc(pid).get();
    if (!p.exists) continue;
    const pd = p.data();
    if (pd.telegramChatId && pd.notificationsTelegram !== false) promises.push(sendTelegram(pd.telegramChatId, msg));
    if (pd.email && pd.notificationsEmail !== false) promises.push(sendEmail(pd.email, 'CEE — Both Players Ready!', html));
    promises.push(logNotif(fixtureId, pid, 'both', 'BOTH_READY', 'sent', null, {
      messageText: msg, emailSubject: 'CEE — Both Players Ready!', emailHtmlBody: html,
      telegramChatId: pd.telegramChatId || null, email: pd.email || null
    }));
  }
  await Promise.allSettled(promises);
}

async function _notifyPartnerReady(otherId, fix, fixtureId) {
  if (!otherId) return;
  const p = await db.collection('players').doc(otherId).get();
  if (!p.exists) return;
  const pd  = p.data();
  const msg = `⏳ <b>Your opponent is Ready!</b>\n\nPlease log in to the CEE Player Hub and click Ready to start the match.`;
  const html = `<p>⏳ Your opponent has clicked Ready for your upcoming fixture.</p>
    <p>Please log in to the <strong>CEE Player Hub</strong> and click <strong>Ready</strong> to start the match.</p>`;
  if (pd.telegramChatId && pd.notificationsTelegram !== false) await sendTelegram(pd.telegramChatId, msg);
  if (pd.email && pd.notificationsEmail !== false) await sendEmail(pd.email, 'CEE — Your Opponent is Ready!', html);
  await logNotif(fixtureId, otherId, 'both', 'PARTNER_READY', 'sent', null, {
    messageText: msg, emailSubject: 'CEE — Your Opponent is Ready!', emailHtmlBody: html,
    telegramChatId: pd.telegramChatId || null, email: pd.email || null
  });
}

async function _sendMatchNotifications(type, fixtureId, playerAId, playerBId, seasonId) {
  const fetchPlayer = async id => {
    if (!id) return null;
    const d = await db.collection('players').doc(id).get();
    return d.exists ? { id: d.id, ...d.data() } : null;
  };
  const pA = await fetchPlayer(playerAId);
  const pB = await fetchPlayer(playerBId);
  const adminEmail = env.admin && env.admin.email;
  const adminChat  = env.telegram && env.telegram.admin_chat_id;

  const notifyPlayer = async (p, subject, html, tg) => {
    if (!p) return;
    if (p.email && p.notificationsEmail !== false) await sendEmail(p.email, subject, html);
    if (p.telegramChatId && p.notificationsTelegram !== false) await sendTelegram(p.telegramChatId, tg);
    await logNotif(fixtureId, p.id, 'both', type, 'sent', null, {
      messageText: tg, emailSubject: subject, emailHtmlBody: html,
      telegramChatId: p.telegramChatId || null, email: p.email || null
    });
  };

  if (type === 'WINDOW_OPEN') {
    const h = `<p>🟢 Your match window is now <strong>OPEN</strong>!</p><p>Log in to the CEE Player Hub, click Ready, and play your fixture.</p>`;
    const t = `🟢 <b>Match window OPEN!</b>\nLog in to the CEE Player Hub and click Ready.`;
    await notifyPlayer(pA,'CEE — Match Window Open!',h,t);
    await notifyPlayer(pB,'CEE — Match Window Open!',h,t);
  }
  if (type === 'FORFEIT_APPLIED') {
    const h = `<p>⚠️ A forfeit has been applied to your fixture because one or both players did not complete the required steps within the match window.</p><p>Check the CEE website for the final result.</p>`;
    const t = `⚠️ <b>Forfeit applied to your fixture.</b>\nA player did not complete the required steps in time. Check the CEE website for the result.`;
    await notifyPlayer(pA,'CEE — Forfeit Applied',h,t);
    await notifyPlayer(pB,'CEE — Forfeit Applied',h,t);
    if (adminChat) await sendTelegram(adminChat, `⚠️ Forfeit applied to fixture ${fixtureId}`);
  }
  if (type === 'RESULT_PENDING') {
    if (adminEmail) await sendEmail(adminEmail,'CEE — Result Awaiting Approval',
      `<p>A match result is ready for your review in the <strong>Result Queue</strong>.</p>
       <div class="hl">Fixture ID: ${fixtureId}</div>
       <p>Auto-approve triggers in 45 minutes if no action is taken.</p>`);
    if (adminChat) await sendTelegram(adminChat,
      `📋 <b>Result awaiting approval</b>\nFixture: ${fixtureId}\nAuto-approves in 45 minutes.`);
  }
  if (type === 'RESULT_APPROVED') {
    const h = `<p>✅ Your match result has been <strong>approved</strong>!</p><p>Check the updated standings on the CEE website.</p>`;
    const t = `✅ <b>Match result approved!</b>\nCheck the updated standings on the CEE website.`;
    await notifyPlayer(pA,'CEE — Result Approved',h,t);
    await notifyPlayer(pB,'CEE — Result Approved',h,t);
  }
  if (type === 'DISPUTE_OPENED') {
    const h = `<p>⚖️ A <strong>dispute</strong> has been opened for your match.</p><p>The admin will review screenshots and statements. Auto-resolves in 72 hours if admin takes no action.</p>`;
    const t = `⚖️ <b>Dispute opened</b> for your fixture.\nAdmin will review. Auto-resolves in 72 hours.`;
    await notifyPlayer(pA,'CEE — Dispute Opened',h,t);
    await notifyPlayer(pB,'CEE — Dispute Opened',h,t);
    if (adminChat) await sendTelegram(adminChat,`⚖️ <b>Dispute opened</b>\nFixture: ${fixtureId}\nRequires review within 72 hours.`);
    if (adminEmail) await sendEmail(adminEmail,'CEE — Dispute Opened',
      `<p>⚖️ A dispute has been opened for fixture <strong>${fixtureId}</strong>.</p>
       <p>Please review in the admin Disputes tab. Auto-resolves as 0–0 in 72 hours.</p>`);
  }
  if (type === 'DISPUTE_AUTO_RESOLVED') {
    const h = `<p>⚖️ Your dispute has been <strong>auto-resolved as a 0–0 draw</strong> after 72 hours without admin action.</p><p>The final result has been recorded. Check the CEE website for updated standings.</p>`;
    const t = `⚖️ <b>Dispute auto-resolved</b> (72hr)\nResult: 0–0 draw. Check standings on the CEE website.`;
    await notifyPlayer(pA,'CEE — Dispute Auto-Resolved',h,t);
    await notifyPlayer(pB,'CEE — Dispute Auto-Resolved',h,t);
    if (adminChat) await sendTelegram(adminChat,`⚖️ <b>Dispute auto-resolved</b> (72hr)\nFixture: ${fixtureId}\nResult: 0–0 draw`);
  }
  if (type === 'REPLAY_SCHEDULED') {
    const h = `<p>🔄 A <strong>replay</strong> has been scheduled for your fixture.</p><p>Check the CEE Player Hub for the new match window details.</p>`;
    const t = `🔄 <b>Replay scheduled</b>\nCheck the CEE Player Hub for your new match window.`;
    await notifyPlayer(pA,'CEE — Replay Scheduled',h,t);
    await notifyPlayer(pB,'CEE — Replay Scheduled',h,t);
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
  return sorted;
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
    if (!player) return res.json({ success:false, message:'Player not found. Check your gaming tag.' });

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
      if (attempts>=3) {
        upd.pinLockoutUntil=toTS(nowWAT().plus({minutes:30}));
        upd.pinFailAttempts=0;
        const newLockCount=(secrets.pinLockoutCount||0)+1;
        upd.pinLockoutCount=newLockCount;
        if (newLockCount>=2) {
          const adminChat=env.telegram&&env.telegram.admin_chat_id;
          if (adminChat) sendTelegram(adminChat,
            `🔐 <b>Repeated PIN lockouts</b>\nPlayer: ${player.clubName||player.gameName}\n${newLockCount} lockouts triggered.`
          ).catch(()=>{});
        }
      }
      await db.collection('playerSecrets').doc(player.id).update(upd);
      const remaining=Math.max(0,3-attempts);
      return res.json({ success:false, message:`Incorrect PIN. ${remaining>0?remaining+' attempt(s) remaining.':'Account locked for 30 minutes.'}` });
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
// POST /submitScore — Gemini Vision AI, AC-1 club match, SHA-256 dedup
// NOI-2: timing check BEFORE _crossValidateScores
// ═══════════════════════════════════════════════════════════════════════════
app.post('/submitScore', async (req, res) => {
  const { fixtureId, playerId, isHome, imageData, mediaType } = req.body;
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

    let ai={ isEfootballResultScreen:false,homeGoals:null,awayGoals:null,confidence:0,homeClubName:null,awayClubName:null,isPlausibleScore:false,isFullResultScreen:false };
    try {
      const geminiUrl=`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${env.gemini.key}`;
      const cr=await fetch(geminiUrl,{
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({
          contents:[{parts:[
            {inline_data:{mime_type:mediaType||'image/jpeg',data:imageData}},
            {text:`You are analyzing an eFootball (soccer video game) post-match result screen.\nRespond ONLY in JSON, no other text, no markdown:\n{\n  "isEfootballResultScreen": true/false,\n  "isFullResultScreen": true/false,\n  "homeGoals": <integer or null>,\n  "awayGoals": <integer or null>,\n  "homeClubName": "<club name or null>",\n  "awayClubName": "<club name or null>",\n  "isPlausibleScore": true/false,\n  "confidence": <float 0.0-1.0>\n}\nRules:\n- isEfootballResultScreen: true only if clearly eFootball post-match result screen\n- isFullResultScreen: true only if shows complete final result\n- homeGoals/awayGoals: final score integers, null if not readable\n- isPlausibleScore: false if GD>=10 or either score>20\n- confidence: 1.0=certain, 0.0=cannot read\n- Set all false/null/0.0 if not eFootball result screen`}
          ]}],
          generationConfig:{maxOutputTokens:300,temperature:0}
        })
      });
      const cd=await cr.json();
      const raw=(cd.candidates&&cd.candidates[0]&&cd.candidates[0].content&&cd.candidates[0].content.parts&&cd.candidates[0].content.parts[0]&&cd.candidates[0].content.parts[0].text)||'{}';
      ai=JSON.parse(raw.replace(/```json|```/g,'').trim());
    } catch(aiErr){ console.error('[CEE] Gemini Vision error:',aiErr.message); }

    if (!ai.isEfootballResultScreen||!ai.isFullResultScreen) {
      await audit('ANTICHEAT_INVALID_SCREENSHOT',fixtureId,'fixture',`Player ${playerId} submitted non-eFootball screenshot`);
      return res.json({ success:false, message:'Not a valid eFootball result screen. Upload the correct screenshot.' });
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

    const conf=ai.confidence||0;
    let flagged=false, flagReason='';
    if (conf<0.60) {
      const retryKey=isHome?'playerARetryCount':'playerBRetryCount';
      const retries=fix[retryKey]||0;
      if (retries>=1){ flagged=true; flagReason='Low AI confidence after retry — admin review required'; }
      else { await fixRef.update({[retryKey]:retries+1}); return res.json({ success:false,retry:true,confidence:conf,message:`Screenshot unclear (${Math.round(conf*100)}% confidence). Upload a clearer result screen. 1 retry remaining.` }); }
    } else if (conf<0.85){ flagged=true; flagReason=`AI confidence ${Math.round(conf*100)}% — below auto-accept threshold`; }

    const fname=`screenshots/${fixtureId}/${playerId}/${Date.now()}.jpg`;
    const bucket=storage.bucket(), file=bucket.file(fname);
    await file.save(imgBuf,{metadata:{contentType:mediaType||'image/jpeg'}});
    const [ssUrl]=await file.getSignedUrl({action:'read',expires:'03-01-2030'});

    const scoreStr=(ai.homeGoals!==null&&ai.awayGoals!==null)?`${ai.homeGoals}-${ai.awayGoals}`:'unknown';
    const sealed=crypto.createHash('sha256').update(scoreStr+fixtureId).digest('hex');
    const nowFV=admin.firestore.FieldValue.serverTimestamp();
    const update={};
    if (isHome){ Object.assign(update,{playerAScoreSealed:sealed,playerAScreenshotUrl:ssUrl,playerASubmittedAt:nowFV,aiConfidenceA:conf,aiExtractedA:{home:ai.homeGoals,away:ai.awayGoals},imageHashA:imgHash}); }
    else       { Object.assign(update,{playerBScoreSealed:sealed,playerBScreenshotUrl:ssUrl,playerBSubmittedAt:nowFV,aiConfidenceB:conf,aiExtractedB:{home:ai.homeGoals,away:ai.awayGoals},imageHashB:imgHash}); }
    if (flagged){ update.screenshotFlaggedForReview=true; update.screenshotFlagReason=flagReason; }
    await fixRef.update(update);

    const fresh=(await fixRef.get()).data();
    if (fresh.playerASubmittedAt&&fresh.playerBSubmittedAt) {
      // NOI-2: timing check FIRST so collusionFlagTime is visible inside _crossValidateScores
      const tsA=fresh.playerASubmittedAt.toDate().getTime();
      const tsB=fresh.playerBSubmittedAt.toDate().getTime();
      const diff=Math.abs(tsA-tsB)/1000;
      if (diff<30) {
        await fixRef.update({ collusionFlagTime:true, collusionFlagTimeDetail:`Both screenshots within ${diff.toFixed(1)}s` });
        await audit('ANTICHEAT_FLAG',fixtureId,'fixture',`Suspicious: both screenshots within ${diff.toFixed(1)}s`);
      } else if (diff>720) {
        await fixRef.update({ lateSubmissionFlag:true, lateSubmissionDetail:`${Math.round(diff/60)} min gap` });
        await audit('ANTICHEAT_FLAG',fixtureId,'fixture',`Suspicious: ${Math.round(diff/60)} min gap`);
      }
      await _crossValidateScores(fixtureId,fresh);
    } else { await logNotif(fixtureId,playerId,'telegram','SUBMISSION_RECEIVED','sent'); }

    return res.json({ success:true, confidence:conf, message:'Screenshot sealed. Awaiting opponent submission.' });
  } catch(e){ console.error('[CEE] submitScore:',e); return res.status(500).json({ success:false, message:'Server error: '+e.message }); }
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
// POST /sendNotification | /retryNotification | /retryAllFailed | /testNotification
// ═══════════════════════════════════════════════════════════════════════════
app.post('/sendNotification', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { recipientId, message, channel } = req.body;
  try {
    if (recipientId==='all') {
      const sid=await getSeasonId();
      const players=sid?await getPlayers(sid):[];
      for (const p of players) {
        if ((!channel||channel==='email'||channel==='both')&&p.email) await sendEmail(p.email,'CEE — Announcement',`<p>${message}</p>`);
        if ((!channel||channel==='telegram'||channel==='both')&&p.telegramChatId) await sendTelegram(p.telegramChatId,message);
      }
    } else if (recipientId) {
      const pd=await db.collection('players').doc(recipientId).get();
      if (pd.exists) {
        const p=pd.data();
        if ((!channel||channel==='email'||channel==='both')&&p.email) await sendEmail(p.email,'CEE — Notification',`<p>${message}</p>`);
        if ((!channel||channel==='telegram'||channel==='both')&&p.telegramChatId) await sendTelegram(p.telegramChatId,message);
      }
    }
    return res.json({ success:true });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
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
  try {
    await sendEmail(env.admin.email,'CEE — Test Notification','<p>✅ Email notifications are working correctly.</p>');
    if (env.telegram&&env.telegram.admin_chat_id) await sendTelegram(env.telegram.admin_chat_id,'✅ CEE Telegram test — working!');
    return res.json({ success:true, message:'Test notifications sent.' });
  } catch(e){ return res.status(500).json({ success:false, message:e.message }); }
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
    const playerRef=await db.collection('players').add({
      seasonId, gameName:reg.gameName||'', clubName:reg.clubName||'',
      initials:reg.initials||(reg.gameName||'').substring(0,2).toUpperCase(),
      email:reg.email||'', telegramUsername:reg.telegramUsername||'',
      telegramChatId:reg.telegramChatId||null, notificationsEmail:true, notificationsTelegram:true,
      registrationId:regId, legacyId:null,
      stats:{pts:0,mp:0,pld:0,w:0,d:0,l:0,gf:0,ga:0,gd:0,goals:0},
      rank:null, knockoutStatus:null, createdAt:admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection('playerSecrets').doc(playerRef.id).set(
      {pinHash,pinFailAttempts:0,pinLockoutUntil:null,pinLockoutCount:0});
    await regDoc.ref.update({status:'approved',playerId:playerRef.id,approvedAt:admin.firestore.FieldValue.serverTimestamp()});
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
    return res.json({ success:true, playerId:playerRef.id });
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
// POST /suggestInitials — AI-powered initials suggestion
// ═══════════════════════════════════════════════════════════════════════════
app.post('/suggestInitials', async (req, res) => {
  if (!assertAdminSecret(req,res)) return;
  const { gameName, clubName } = req.body;
  const name=gameName||clubName||'';
  if (!name) return res.status(400).json({ success:false, message:'Missing name' });
  const words=name.trim().split(/\s+/);
  const initials=words.length>=2
    ? (words[0][0]+words[words.length-1][0]).toUpperCase()
    : name.substring(0,2).toUpperCase();
  return res.json({ success:true, initials });
});

// ═══════════════════════════════════════════════════════════════════════════
// POST /telegramWebhook — /start, /status, /fixtures — SEC-1: direct queries
// ═══════════════════════════════════════════════════════════════════════════
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
      if (!found) { await sendTelegram(chatId,`❌ Tag <b>${tag}</b> not found. Double-check your gaming tag exactly as registered, or contact the admin.`); return; }
      await db.collection('players').doc(found.id).update({ telegramChatId:chatId, telegramUsername:username, notificationsTelegram:true });
      await sendTelegram(chatId,
        `✅ <b>Telegram linked successfully!</b>\n\nYou'll now receive match notifications here for <b>${found.clubName||found.gameName}</b>.\n\nCommands:\n/status — your current season stats\n/fixtures — upcoming matches`);
      await audit('TELEGRAM_LINKED',found.id,'player',`ChatId ${chatId} linked via /start`);
    }
    else if (text==='/status') {
      const seasonId=await getSeasonId();
      if (!seasonId){ await sendTelegram(chatId,'⚠️ No active season.'); return; }
      const snap=await db.collection('players').where('seasonId','==',seasonId).where('telegramChatId','==',chatId).limit(1).get();
      if (snap.empty){ await sendTelegram(chatId,'❌ Account not linked. Send /start YourTag'); return; }
      const p=snap.docs[0].data(), s=p.stats||{};
      await sendTelegram(chatId,
        `📊 <b>${p.clubName||p.gameName}</b>\nRank: #${p.rank||'—'}\nPoints: ${s.pts||0}\nMP: ${s.mp||0} | W: ${s.w||0} D: ${s.d||0} L: ${s.l||0}\nGF: ${s.gf||0} GA: ${s.ga||0} GD: ${s.gd>=0?'+':''}${s.gd||0}`);
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
  } catch(e){ console.error('[CEE] telegramWebhook:',e.message); }
});

// ═══════════════════════════════════════════════════════════════════════════
// ── SCHEDULED JOBS (node-cron replaces Firebase pubsub.schedule) ──────────
// All times are WAT (Africa/Lagos = UTC+1). node-cron runs in server local
// time, so we use UTC patterns and subtract 1 hour where needed.
// ═══════════════════════════════════════════════════════════════════════════

// ── windowManager — every 15 min ─────────────────────────────────────────
async function runWindowManager() {
  const seasonId=await getSeasonId(); if (!seasonId) return;
  const seasonDoc=await db.collection('seasons').doc(seasonId).get();
  if (!seasonDoc.exists||seasonDoc.data().forceMajeure) { console.log('[CEE] Force Majeure active — skipping window management'); return; }
  const nowTs=nowTS();

  const toOpen=await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','==','scheduled').where('windowOpenTime','<=',nowTs).get();
  const batch=db.batch(); const notifications=[];
  toOpen.forEach(doc => {
    const f=doc.data();
    if (f.windowCloseTime&&nowTs.toMillis()>f.windowCloseTime.toMillis()) return;
    batch.update(doc.ref,{status:'window_open'});
    notifications.push({type:'WINDOW_OPEN',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId});
  });

  const openFix=await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','in',['window_open','ready_pending']).get();
  openFix.forEach(doc => {
    const f=doc.data(); if (!f.windowOpenTime) return;
    const openedAt=fromTS(f.windowOpenTime), hoursOpen=nowWAT().diff(openedAt,'hours').hours;
    if (!f.playerAReadyAt&&!f.playerBReadyAt&&hoursOpen>=2&&hoursOpen<2.25&&!f.reminder2hSent) {
      batch.update(doc.ref,{reminder2hSent:true});
      notifications.push({type:'READY_REMINDER_1',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId});
    }
    const oneReady=(!!f.playerAReadyAt)!==(!!f.playerBReadyAt);
    if (oneReady&&hoursOpen>=3&&hoursOpen<3.25&&!f.reminder3hSent) {
      batch.update(doc.ref,{reminder3hSent:true});
      notifications.push({type:'READY_REMINDER_2',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId});
    }
    if (f.windowCloseTime) {
      const minsToClose=fromTS(f.windowCloseTime).diff(nowWAT(),'minutes').minutes;
      if (minsToClose>=55&&minsToClose<70&&!f.warn1hSent) {
        batch.update(doc.ref,{warn1hSent:true});
        notifications.push({type:'DEADLINE_REMINDER',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId});
      }
    }
  });

  const toClose=await db.collection('fixtures').where('seasonId','==',seasonId)
    .where('status','in',['window_open','ready_pending','in_progress'])
    .where('windowCloseTime','<=',nowTs).get();
  const seenAutoApprove=[];
  toClose.forEach(doc => {
    const f=doc.data(); let result=null;
    const base={adminApproved:true,autoApprovedAt:admin.firestore.FieldValue.serverTimestamp()};
    if (!f.playerAReadyAt&&!f.playerBReadyAt)               { result='DNP';       batch.update(doc.ref,{...base,status:'approved',result,playerAGoals:0,playerBGoals:0,done:true,isForfeit:false}); }
    else if (f.playerAReadyAt&&!f.playerBReadyAt)            { result='FORFEIT_B'; batch.update(doc.ref,{...base,status:'approved',result,playerAGoals:3,playerBGoals:0,done:true,isForfeit:true}); notifications.push({type:'FORFEIT_APPLIED',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId}); }
    else if (!f.playerAReadyAt&&f.playerBReadyAt)            { result='FORFEIT_A'; batch.update(doc.ref,{...base,status:'approved',result,playerAGoals:0,playerBGoals:3,done:true,isForfeit:true}); notifications.push({type:'FORFEIT_APPLIED',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId}); }
    else if (f.bothReadyAt&&!f.playerASubmittedAt&&!f.playerBSubmittedAt){ result='DNP'; batch.update(doc.ref,{...base,status:'approved',result,playerAGoals:0,playerBGoals:0,done:true,isForfeit:false}); }
    else if (f.playerASubmittedAt&&!f.playerBSubmittedAt)    { result='FORFEIT_B'; batch.update(doc.ref,{...base,status:'approved',result,playerAGoals:3,playerBGoals:0,done:true,isForfeit:true}); notifications.push({type:'FORFEIT_APPLIED',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId}); }
    else if (!f.playerASubmittedAt&&f.playerBSubmittedAt)    { result='FORFEIT_A'; batch.update(doc.ref,{...base,status:'approved',result,playerAGoals:0,playerBGoals:3,done:true,isForfeit:true}); notifications.push({type:'FORFEIT_APPLIED',fixtureId:doc.id,pA:f.playerAId,pB:f.playerBId}); }
    if (result){ seenAutoApprove.push(doc.id); audit('WINDOW_CLOSED_AUTO',doc.id,'fixture',`Result: ${result}`).catch(()=>{}); }
  });

  await batch.commit();
  for (const n of notifications) await _sendMatchNotifications(n.type,n.fixtureId,n.pA,n.pB,seasonId);
  if (seenAutoApprove.length>0) {
    await db.collection('seasons').doc(seasonId).update({standingsDirty:true}).catch(()=>{});
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
// START SERVER
// ═══════════════════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[CEE] Backend running on port ${PORT}`);
  console.log('[CEE] Scheduled jobs active: windowManager(15m), submissionDeadlineEnforcer(10m),');
  console.log('[CEE]   autoApprover(5m), disputeAutoResolver(30m), doubleConsentExpiryEnforcer(30m),');
  console.log('[CEE]   swissPairingEngine(6h), registrationDeadlineChecker(daily),');
  console.log('[CEE]   dailyAdminDigest(08:00 WAT), replayAutoScheduler(06:00 WAT),');
  console.log('[CEE]   notificationRetryWorker(2h)');
  console.log('[CEE] Firestore listeners: fixtures, registrations');
});
