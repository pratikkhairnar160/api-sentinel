/**
 * validator/services/twilio.js
 * Non-destructive Twilio + Shopify + Mailgun validators
 * All probes are read-only with zero side effects
 */
'use strict';

const { BaseValidator } = require('../base');

// ─── Twilio ───────────────────────────────────────────────────────────────

class TwilioValidator extends BaseValidator {
  constructor(options = {}) {
    super('twilio_account_sid', 'Twilio', options);
  }

  /**
   * Probe: GET /Accounts/{SID} — returns account info, purely read-only
   * A valid SID + AuthToken → 200, invalid → 401
   */
  async probe({ accountSid, authToken }) {
    if (!accountSid || !authToken) {
      return this._invalidResult('Need both Account SID and Auth Token for Twilio validation');
    }

    const credentials = Buffer.from(`${accountSid}:${authToken}`).toString('base64');
    const res = await this.http.get(
      `https://api.twilio.com/2010-04-01/Accounts/${accountSid}.json`,
      { headers: { Authorization: `Basic ${credentials}` } }
    );

    if (res.status === 200 && res.data?.sid) {
      return this._validResult({
        accountSid:   res.data.sid,
        friendlyName: res.data.friendly_name,
        status:       res.data.status,
        type:         res.data.type,
        note: res.data.status === 'active'
          ? '⚠️ Active account — can make calls and send SMS'
          : `Account status: ${res.data.status}`,
      });
    }

    if (res.status === 401) return this._invalidResult('Authentication failed — invalid SID or AuthToken');
    if (res.status === 404) return this._invalidResult('Account SID not found');
    if (res.status === 429) return this._rateLimitResult();

    return this._errorResult(`Unexpected status: ${res.status}`);
  }
}

// ─── Shopify ──────────────────────────────────────────────────────────────

class ShopifyValidator extends BaseValidator {
  constructor(options = {}) {
    super('shopify_token', 'Shopify', options);
  }

  /**
   * Probe: GET /admin/api/2024-01/shop.json
   * Returns basic store info — read-only, no side effects
   * Requires the shop domain to construct the URL
   */
  async probe({ token, shopDomain }) {
    if (!shopDomain) {
      return {
        status: 'unknown',
        message: 'Shop domain required for Shopify validation — cannot validate without target domain context',
        testedAt: new Date().toISOString(),
        service: this.serviceName,
      };
    }

    const domain = shopDomain.replace(/https?:\/\//, '').replace(/\/$/, '');
    const res = await this.http.get(
      `https://${domain}/admin/api/2024-01/shop.json`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );

    if (res.status === 200 && res.data?.shop) {
      const shop = res.data.shop;
      return this._validResult({
        shopName:  shop.name,
        email:     shop.email,
        domain:    shop.domain,
        planName:  shop.plan_name,
        country:   shop.country_name,
        currency:  shop.currency,
        note: '⚠️ Valid admin token — has access to store orders, customers, and products',
      });
    }

    if (res.status === 401 || res.status === 403) {
      return this._invalidResult(`Authentication failed (${res.status}) — token invalid or revoked`);
    }
    if (res.status === 402) {
      return this._restrictedResult({ note: 'Store requires payment — token may be valid' });
    }
    if (res.status === 429) return this._rateLimitResult();

    return this._errorResult(`Unexpected status: ${res.status}`);
  }
}

// ─── Mailgun ──────────────────────────────────────────────────────────────

class MailgunValidator extends BaseValidator {
  constructor(options = {}) {
    super('mailgun_api_key', 'Mailgun', options);
  }

  /**
   * Probe: GET /v3/domains — lists configured sending domains
   * Read-only, no side effects
   */
  async probe(apiKey) {
    const credentials = Buffer.from(`api:${apiKey}`).toString('base64');
    const res = await this.http.get('https://api.mailgun.net/v3/domains', {
      headers: { Authorization: `Basic ${credentials}` },
    });

    if (res.status === 200 && res.data?.items !== undefined) {
      const domains = res.data.items || [];
      return this._validResult({
        domainCount: domains.length,
        domains: domains.slice(0, 5).map(d => d.name),
        note: `⚠️ Valid key — can send email from ${domains.length} configured domain(s)`,
      });
    }

    if (res.status === 401) return this._invalidResult('Unauthorized — key is invalid or revoked');
    if (res.status === 429) return this._rateLimitResult();

    return this._errorResult(`Unexpected status: ${res.status}`);
  }
}

module.exports = { TwilioValidator, ShopifyValidator, MailgunValidator };
