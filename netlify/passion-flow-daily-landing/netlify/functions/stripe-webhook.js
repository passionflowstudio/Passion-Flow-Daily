// Stripe webhook — ZERO npm dependencies.
//
// Why: this site is deployed by drag-and-drop, which has no build step, so `npm install`
// never runs and any `require('stripe')` / `require('firebase-admin')` would crash the
// function before it did anything. Everything here uses only Node built-ins (crypto) plus
// global fetch (Node 18+, which is Netlify's default runtime).
//
// What it does: verifies Stripe's signature, then writes entitlement fields
// (isPro / subscriptionStatus / stripeCustomerId) straight to Firestore over the REST API
// using a Google service-account token. Those fields are blocked for browsers by the
// Firestore rules on purpose — the server is the only thing allowed to grant Pro.
//
// Required Netlify environment variables:
//   STRIPE_SECRET_KEY        (not strictly needed here, kept for parity/future use)
//   STRIPE_WEBHOOK_SECRET    whsec_...   from Stripe > Developers > Webhooks > your endpoint
//   FIREBASE_SERVICE_ACCOUNT the ENTIRE service-account JSON, pasted as one line

const crypto = require('crypto');

// Netlify currently stores these with a trailing "1" (STRIPE_WEBHOOK_SECRET1 /
// STRIPE_SECRET_KEY1). Accept either spelling so the function works no matter which
// name is present — a mismatch here silently fails signature verification with a 400.
const WEBHOOK_SECRET =
  process.env.STRIPE_WEBHOOK_SECRET || process.env.STRIPE_WEBHOOK_SECRET1;
const STRIPE_SECRET_KEY =
  process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY1;

/* ── Stripe signature verification ─────────────────────────────────────────── */
function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;

  let timestamp = null;
  const signatures = [];
  sigHeader.split(',').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key === 't') timestamp = val;
    if (key === 'v1') signatures.push(val);
  });
  if (!timestamp || signatures.length === 0) return false;

  // Replay protection: reject anything older than 5 minutes.
  const age = Math.floor(Date.now() / 1000) - Number(timestamp);
  if (!Number.isFinite(age) || Math.abs(age) > 300) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`, 'utf8')
    .digest('hex');

  // Constant-time compare against every provided v1 signature.
  return signatures.some((sig) => {
    const a = Buffer.from(sig, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}

/* ── Google service-account auth (JWT → OAuth access token) ────────────────── */
function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

let cachedToken = null; // { token, expiresAt } — reused across warm invocations

async function getAccessToken(serviceAccount) {
  if (cachedToken && Date.now() < cachedToken.expiresAt - 60000) {
    return cachedToken.token;
  }

  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = base64url(
    JSON.stringify({
      iss: serviceAccount.client_email,
      scope: 'https://www.googleapis.com/auth/datastore',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600,
      iat: now,
    })
  );

  const signingInput = `${header}.${claim}`;
  // Env vars usually store the key with literal \n sequences — restore real newlines.
  const privateKey = String(serviceAccount.private_key).replace(/\\n/g, '\n');
  const signature = crypto
    .createSign('RSA-SHA256')
    .update(signingInput)
    .sign(privateKey, 'base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const assertion = `${signingInput}.${signature}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:
      'grant_type=' +
      encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') +
      '&assertion=' +
      assertion,
  });

  const json = await res.json();
  if (!json.access_token) {
    throw new Error('Google token request failed: ' + JSON.stringify(json));
  }

  cachedToken = { token: json.access_token, expiresAt: Date.now() + 3500 * 1000 };
  return cachedToken.token;
}

/* ── Firestore REST helpers ────────────────────────────────────────────────── */
function docUrl(projectId, uid) {
  return `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${uid}`;
}

// Merge-writes only the given fields (updateMask = merge semantics).
async function patchUserFields(projectId, token, uid, fields) {
  const keys = Object.keys(fields);
  const mask = keys.map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join('&');

  const firestoreFields = {};
  keys.forEach((k) => {
    const v = fields[k];
    if (typeof v === 'boolean') firestoreFields[k] = { booleanValue: v };
    else if (v === null || v === undefined) firestoreFields[k] = { nullValue: null };
    else firestoreFields[k] = { stringValue: String(v) };
  });

  const res = await fetch(`${docUrl(projectId, uid)}?${mask}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ fields: firestoreFields }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Firestore PATCH failed (${res.status}): ${text}`);
  }
  return true;
}

// Finds user document ids by stripeCustomerId (used by renewal/cancel events).
async function findUidsByCustomerId(projectId, token, customerId) {
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: 'users' }],
          where: {
            fieldFilter: {
              field: { fieldPath: 'stripeCustomerId' },
              op: 'EQUAL',
              value: { stringValue: customerId },
            },
          },
          limit: 25,
        },
      }),
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Firestore runQuery failed (${res.status}): ${text}`);
  }

  const rows = await res.json();
  const uids = [];
  (rows || []).forEach((row) => {
    if (row && row.document && row.document.name) {
      uids.push(row.document.name.split('/').pop());
    }
  });
  return uids;
}

/* ── Handler ───────────────────────────────────────────────────────────────── */
exports.handler = async (event) => {
  // Stripe signs the RAW body — decode base64 if Netlify encoded it, never re-serialize.
  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body || '', 'base64').toString('utf8')
    : event.body || '';

  const sig =
    (event.headers && (event.headers['stripe-signature'] || event.headers['Stripe-Signature'])) ||
    '';

  if (!WEBHOOK_SECRET) {
    console.error(
      '[stripe-webhook] No signing secret found. Set STRIPE_WEBHOOK_SECRET (or STRIPE_WEBHOOK_SECRET1) in Netlify env vars.'
    );
    return { statusCode: 500, body: 'Server misconfigured: missing signing secret' };
  }

  if (!verifyStripeSignature(rawBody, sig, WEBHOOK_SECRET)) {
    console.error('[stripe-webhook] signature verification failed');
    return { statusCode: 400, body: 'Invalid signature' };
  }

  let stripeEvent;
  try {
    stripeEvent = JSON.parse(rawBody);
  } catch (err) {
    return { statusCode: 400, body: 'Invalid JSON' };
  }

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } catch (err) {
    console.error('[stripe-webhook] FIREBASE_SERVICE_ACCOUNT is missing or not valid JSON');
    return { statusCode: 500, body: 'Server misconfigured' };
  }

  const projectId = serviceAccount.project_id || 'passion-flow-daily';
  const data = (stripeEvent.data && stripeEvent.data.object) || {};

  try {
    const token = await getAccessToken(serviceAccount);

    switch (stripeEvent.type) {
      // Checkout finished (trial started or paid) — the main grant path.
      case 'checkout.session.completed': {
        const uid = data.client_reference_id;
        if (!uid) {
          console.error('[stripe-webhook] checkout.session.completed with no client_reference_id');
          break;
        }
        await patchUserFields(projectId, token, uid, {
          isPro: true,
          subscriptionStatus: 'active',
          stripeCustomerId: data.customer || '',
        });
        console.log('[stripe-webhook] isPro=true set for uid:', uid);
        break;
      }

      // Renewal succeeded.
      case 'invoice.payment_succeeded': {
        if (!data.customer) break;
        const uids = await findUidsByCustomerId(projectId, token, data.customer);
        for (const uid of uids) {
          await patchUserFields(projectId, token, uid, {
            isPro: true,
            subscriptionStatus: 'active',
          });
        }
        break;
      }

      // Payment failed — revoke.
      case 'invoice.payment_failed': {
        if (!data.customer) break;
        const uids = await findUidsByCustomerId(projectId, token, data.customer);
        for (const uid of uids) {
          await patchUserFields(projectId, token, uid, {
            isPro: false,
            subscriptionStatus: 'past_due',
          });
        }
        break;
      }

      // Subscription cancelled/expired — revoke.
      case 'customer.subscription.deleted': {
        if (!data.customer) break;
        const uids = await findUidsByCustomerId(projectId, token, data.customer);
        for (const uid of uids) {
          await patchUserFields(projectId, token, uid, {
            isPro: false,
            subscriptionStatus: 'cancelled',
          });
        }
        break;
      }

      // Status changed (trialing/active keep access, anything else loses it).
      case 'customer.subscription.updated': {
        if (!data.customer) break;
        const status = data.status;
        const active = status === 'active' || status === 'trialing';
        const uids = await findUidsByCustomerId(projectId, token, data.customer);
        for (const uid of uids) {
          await patchUserFields(projectId, token, uid, {
            isPro: active,
            subscriptionStatus: status || 'unknown',
          });
        }
        break;
      }

      default:
        // Unhandled event types are fine — acknowledge so Stripe stops retrying.
        break;
    }
  } catch (err) {
    console.error('[stripe-webhook] processing error:', err && err.message);
    // 500 tells Stripe to retry, which is what we want for transient failures.
    return { statusCode: 500, body: 'Internal error' };
  }

  return { statusCode: 200, body: 'ok' };
};
