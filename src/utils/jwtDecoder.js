/**
 * utils/jwtDecoder.js
 * Safe offline JWT inspection — decodes header + payload without verification.
 * Never contacts external services. Used to enrich JWT findings with claim info.
 */

'use strict';

/**
 * Decode a JWT token into its header, payload, and metadata.
 * This is purely a Base64 decode — it does NOT verify the signature.
 *
 * @param {string} token
 * @returns {{ valid: boolean, header?: object, payload?: object, meta?: object, error?: string }}
 */
function decodeJwt(token) {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Not a string' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: `Expected 3 parts, got ${parts.length}` };
  }

  try {
    const header  = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));

    const now = Math.floor(Date.now() / 1000);
    const isExpired   = payload.exp ? payload.exp < now     : null;
    const notYetValid = payload.nbf ? payload.nbf > now     : null;
    const expiresAt   = payload.exp ? new Date(payload.exp * 1000).toISOString() : null;
    const issuedAt    = payload.iat ? new Date(payload.iat * 1000).toISOString() : null;

    // Sensitive claim detection
    const sensitiveClaims = detectSensitiveClaims(payload);

    return {
      valid: true,
      header,
      payload,
      meta: {
        algorithm:      header.alg   || 'unknown',
        type:           header.typ   || 'JWT',
        issuer:         payload.iss  || null,
        subject:        payload.sub  || null,
        audience:       payload.aud  || null,
        expiresAt,
        issuedAt,
        isExpired,
        notYetValid,
        hasExpiry:      !!payload.exp,
        shortExpiry:    payload.exp ? (payload.exp - (payload.iat || 0)) < 3600 : null,
        sensitiveClaims,
        riskNotes:      buildRiskNotes(header, payload, isExpired),
      },
    };

  } catch (err) {
    return { valid: false, error: `Decode failed: ${err.message}` };
  }
}

/**
 * Base64url decode (JWT uses base64url, not standard base64)
 */
function base64UrlDecode(str) {
  // Add padding
  const padded = str + '='.repeat((4 - str.length % 4) % 4);
  // Replace base64url chars with standard base64
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64, 'base64').toString('utf8');
}

/**
 * Detect claims that commonly carry sensitive data
 */
function detectSensitiveClaims(payload) {
  const sensitive = [];
  const SENSITIVE_KEYS = [
    'email', 'phone', 'name', 'given_name', 'family_name',
    'address', 'birthdate', 'ssn', 'national_id', 'tax_id',
    'role', 'roles', 'permissions', 'scope', 'groups',
    'admin', 'superuser', 'is_staff', 'is_admin',
    'credit_card', 'card_number', 'cvv',
    'password', 'secret', 'api_key', 'token',
  ];

  for (const [key, value] of Object.entries(payload)) {
    if (SENSITIVE_KEYS.some(sk => key.toLowerCase().includes(sk))) {
      sensitive.push({ key, valueType: typeof value });
    }
  }
  return sensitive;
}

/**
 * Build risk notes for the finding
 */
function buildRiskNotes(header, payload, isExpired) {
  const notes = [];

  if (header.alg === 'none') {
    notes.push('🔴 CRITICAL: Algorithm is "none" — signature validation is disabled!');
  }
  if (['HS256', 'HS384', 'HS512'].includes(header.alg)) {
    notes.push('⚠️ Symmetric HMAC algorithm — if secret is weak, token can be forged');
  }
  if (!payload.exp) {
    notes.push('⚠️ No expiry (exp) claim — token never expires');
  }
  if (isExpired === false) {
    notes.push('🔴 Token is currently VALID and not expired');
  }
  if (isExpired === true) {
    notes.push('ℹ️ Token is expired — but signing secret may still be reusable');
  }
  if (payload.role === 'admin' || payload.is_admin || payload.admin === true) {
    notes.push('🔴 Token carries ADMIN role — high privilege');
  }

  return notes;
}

/**
 * Format decoded JWT for display in the GUI detail modal
 * @param {object} decoded — result of decodeJwt()
 * @returns {string} formatted summary
 */
function formatForDisplay(decoded) {
  if (!decoded.valid) return `Invalid JWT: ${decoded.error}`;
  const { header, payload, meta } = decoded;
  const lines = [
    `Algorithm: ${meta.algorithm}`,
    `Issuer:    ${meta.issuer || '—'}`,
    `Subject:   ${meta.subject || '—'}`,
    `Expires:   ${meta.expiresAt || 'Never'}`,
    `Issued:    ${meta.issuedAt || '—'}`,
    `Status:    ${meta.isExpired === null ? 'Unknown' : meta.isExpired ? 'EXPIRED' : 'VALID'}`,
  ];
  if (meta.sensitiveClaims.length > 0) {
    lines.push(`Sensitive claims: ${meta.sensitiveClaims.map(c => c.key).join(', ')}`);
  }
  if (meta.riskNotes.length > 0) {
    lines.push('', 'Risk notes:');
    meta.riskNotes.forEach(n => lines.push(`  ${n}`));
  }
  return lines.join('\n');
}

module.exports = { decodeJwt, formatForDisplay };
