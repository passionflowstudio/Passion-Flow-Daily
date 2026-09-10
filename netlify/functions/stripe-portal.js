// Stripe billing portal redirect — ZERO npm dependencies.
//
// Same reasoning as stripe-webhook.js: drag-and-drop deploys have no build step, so
// `require('stripe')` would crash this function. This talks to Stripe's REST API directly
// using global fetch (Node 18+, Netlify's default runtime).
//
// Required Netlify environment variable:
//   STRIPE_SECRET_KEY   sk_live_... (or sk_test_...)

const STRIPE_API = 'https://api.stripe.com/v1';

// Netlify currently stores this as STRIPE_SECRET_KEY1 (trailing "1"). Accept either
// spelling so a naming mismatch can't silently break the billing portal.
const STRIPE_SECRET_KEY =
  process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY1;

function stripeHeaders() {
  return {
    Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };
}

exports.handler = async (event) => {
  const email =
    event.queryStringParameters && event.queryStringParameters.email;

  if (!email) {
    return { statusCode: 400, body: 'Missing email' };
  }

  if (!STRIPE_SECRET_KEY) {
    console.error(
      '[stripe-portal] No Stripe secret key found. Set STRIPE_SECRET_KEY (or STRIPE_SECRET_KEY1) in Netlify env vars.'
    );
    return { statusCode: 500, body: 'Server misconfigured' };
  }

  try {
    // Look up the customer by email.
    const listRes = await fetch(
      `${STRIPE_API}/customers?email=${encodeURIComponent(email)}&limit=1`,
      { headers: stripeHeaders() }
    );
    const customers = await listRes.json();

    if (!listRes.ok) {
      throw new Error(
        'Stripe customer lookup failed: ' + JSON.stringify(customers)
      );
    }

    if (!customers.data || customers.data.length === 0) {
      return {
        statusCode: 302,
        headers: { Location: '/?portal_error=no_customer' },
        body: '',
      };
    }

    const customerId = customers.data[0].id;

    // Create a billing portal session for that customer.
    const portalRes = await fetch(`${STRIPE_API}/billing_portal/sessions`, {
      method: 'POST',
      headers: stripeHeaders(),
      body:
        'customer=' +
        encodeURIComponent(customerId) +
        '&return_url=' +
        encodeURIComponent('https://passionflowdaily.com'),
    });
    const session = await portalRes.json();

    if (!portalRes.ok || !session.url) {
      throw new Error(
        'Stripe portal session failed: ' + JSON.stringify(session)
      );
    }

    return {
      statusCode: 302,
      headers: { Location: session.url },
      body: '',
    };
  } catch (err) {
    console.error('[stripe-portal] error:', err && err.message);
    return { statusCode: 500, body: 'Error creating billing portal session' };
  }
};
