/**
 * validator/services/stripe.js
 * Non-destructive Stripe key validation
 * Uses a retrieve-by-ID probe with a known-invalid ID —
 * returns auth errors vs object-not-found errors to determine key validity
 */

'use strict';

const { BaseValidator } = require('../base');

class StripeValidator extends BaseValidator {
  constructor(options = {}) {
    super('stripe_live_secret', 'Stripe', options);
  }

  async probe(key) {
    const isLive = key.startsWith('sk_live_');
    const isTest = key.startsWith('sk_test_');
    const isPub  = key.startsWith('pk_');

    if (isPub) {
      // Publishable keys don't need server-side validation
      return this._restrictedResult({
        note: 'Publishable key — intended for client-side use, no secret access',
        keyType: 'publishable',
      });
    }

    // Probe: try to retrieve a payment intent that doesn't exist.
    // A valid key → returns 404 (object not found)
    // An invalid key → returns 401 (authentication failed)
    // This is read-only and completely safe.
    const res = await this.http.get('https://api.stripe.com/v1/payment_intents/pi_sentinel_probe', {
      headers: {
        Authorization: `Bearer ${key}`,
      },
    });

    if (res.status === 401 || res.data?.error?.type === 'authentication_error') {
      return this._invalidResult('Authentication failed — key is invalid or revoked');
    }

    if (res.status === 404 || res.data?.error?.code === 'resource_missing') {
      // Key authenticated successfully — object just doesn't exist (expected)
      const permissions = await this._checkPermissions(key);
      return this._validResult({
        keyType: isLive ? 'live_secret' : 'test_secret',
        environment: isLive ? '⚠️ LIVE/PRODUCTION' : 'Test',
        permissions,
        note: isLive
          ? 'LIVE key — has access to real customer payment data'
          : 'Test key — safe environment, no real payment risk',
      });
    }

    if (res.status === 429) return this._rateLimitResult();

    return this._errorResult(`Unexpected status: ${res.status}`);
  }

  async _checkPermissions(key) {
    // Try to list recent charges (read-only) to assess scope
    try {
      const res = await this.http.get('https://api.stripe.com/v1/charges?limit=1', {
        headers: { Authorization: `Bearer ${key}` },
      });
      if (res.status === 200) return ['charges:read', 'customers:read', 'payments:read'];
      if (res.status === 403) return ['limited_scope'];
    } catch {}
    return ['unknown'];
  }
}

module.exports = { StripeValidator };
