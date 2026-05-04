/**
 * validator/services/google.js
 * Non-destructive Google API key validation
 * Uses a safe, read-only geocoding probe with a known address
 */

'use strict';

const { BaseValidator } = require('../base');

class GoogleValidator extends BaseValidator {
  constructor(options = {}) {
    super('google_api_key', 'Google API Key', options);
  }

  async probe(key) {
    // Safe read-only probe: geocode a well-known public landmark
    // This generates minimal cost (geocoding is cheap) and is read-only
    const res = await this.http.get('https://maps.googleapis.com/maps/api/geocode/json', {
      params: {
        address: 'Googleplex, Mountain View, CA',
        key,
      },
    });

    const body = res.data;
    const status = body?.status;

    if (status === 'OK' || status === 'ZERO_RESULTS') {
      // Key works — determine restriction level
      const isRestricted = res.headers['x-restricted'] === 'true';
      return this._validResult({
        permissions: ['Geocoding API enabled'],
        quotaUsed: body?.results?.length || 0,
        apiStatus: status,
        note: isRestricted ? 'Key has HTTP referrer restrictions' : 'No HTTP referrer restrictions detected',
      });
    }

    if (status === 'REQUEST_DENIED') {
      // Check if it's due to API not enabled vs invalid key
      const msg = body?.error_message || '';
      if (msg.includes('not enabled') || msg.includes('API project')) {
        return this._restrictedResult({
          note: 'Key is valid but Geocoding API is not enabled',
          apiStatus: status,
        });
      }
      return this._invalidResult(`Rejected: ${msg || 'REQUEST_DENIED'}`);
    }

    if (status === 'OVER_QUERY_LIMIT') {
      return this._rateLimitResult();
    }

    if (status === 'INVALID_REQUEST') {
      return this._invalidResult('Invalid key format or malformed request');
    }

    return this._errorResult(`Unknown API status: ${status}`);
  }
}

module.exports = { GoogleValidator };
