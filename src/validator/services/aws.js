/**
 * validator/services/aws.js
 * Non-destructive AWS credential validation
 * Uses STS GetCallerIdentity — the safest possible read-only probe.
 * It ONLY identifies who the key belongs to — no resource access.
 */

'use strict';

const crypto = require('crypto');
const { BaseValidator } = require('../base');

class AwsValidator extends BaseValidator {
  constructor(options = {}) {
    super('aws_access_key', 'AWS IAM Key', options);
  }

  /**
   * Probe using STS GetCallerIdentity
   * This is the canonical "am I authenticated?" check.
   * Every AWS SDK uses this internally — it incurs ZERO cost and no data access.
   */
  async probe(keyPair) {
    // keyPair: { accessKeyId, secretAccessKey }
    const { accessKeyId, secretAccessKey, sessionToken } = keyPair;

    if (!accessKeyId || !secretAccessKey) {
      return this._invalidResult('Incomplete key pair — need both Access Key ID and Secret');
    }

    const endpoint = 'https://sts.amazonaws.com/';
    const payload = 'Action=GetCallerIdentity&Version=2011-06-15';
    const now = new Date();
    const dateStr = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
    const dateOnly = dateStr.slice(0, 8);
    const region = 'us-east-1';
    const service = 'sts';

    // Build AWS Signature v4
    const headers = this._buildAuthHeaders(
      accessKeyId, secretAccessKey, sessionToken,
      endpoint, payload, dateStr, dateOnly, region, service
    );

    const res = await this.http.post(endpoint, payload, { headers });

    if (res.status === 200 && res.data?.includes('GetCallerIdentityResponse')) {
      // Extract account/user info from XML response
      const accountMatch = res.data.match(/<Account>(\d+)<\/Account>/);
      const userMatch    = res.data.match(/<UserId>([^<]+)<\/UserId>/);
      const arnMatch     = res.data.match(/<Arn>([^<]+)<\/Arn>/);

      return this._validResult({
        accountId:  accountMatch?.[1],
        userId:     userMatch?.[1],
        arn:        arnMatch?.[1],
        note: 'STS GetCallerIdentity succeeded — key is valid and active',
      });
    }

    if (res.status === 403 || (res.data && res.data.includes('InvalidClientTokenId'))) {
      return this._invalidResult('InvalidClientTokenId — key does not exist or has been revoked');
    }

    if (res.data && res.data.includes('SignatureDoesNotMatch')) {
      return this._invalidResult('SignatureDoesNotMatch — secret key is incorrect');
    }

    if (res.data && res.data.includes('ExpiredToken')) {
      return this._invalidResult('Temporary credentials have expired');
    }

    if (res.status === 429) {
      return this._rateLimitResult();
    }

    return this._errorResult(`Unexpected response: ${res.status}`);
  }

  // ─── AWS Signature v4 implementation ─────────────────────────────────────

  _buildAuthHeaders(accessKeyId, secretKey, sessionToken, endpoint, payload, dateStr, dateOnly, region, service) {
    const host = new URL(endpoint).host;
    const contentType = 'application/x-www-form-urlencoded';
    const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');

    const canonicalHeaders = [
      `content-type:${contentType}`,
      `host:${host}`,
      `x-amz-date:${dateStr}`,
      sessionToken ? `x-amz-security-token:${sessionToken}` : '',
    ].filter(Boolean).join('\n') + '\n';

    const signedHeaders = ['content-type', 'host', 'x-amz-date',
      ...(sessionToken ? ['x-amz-security-token'] : [])].join(';');

    const canonicalRequest = [
      'POST', '/', '',
      canonicalHeaders, signedHeaders, payloadHash,
    ].join('\n');

    const credentialScope = `${dateOnly}/${region}/${service}/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256', dateStr, credentialScope,
      crypto.createHash('sha256').update(canonicalRequest).digest('hex'),
    ].join('\n');

    const signingKey = this._getSigningKey(secretKey, dateOnly, region, service);
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

    const authorization = [
      `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}`,
      `SignedHeaders=${signedHeaders}`,
      `Signature=${signature}`,
    ].join(', ');

    const headers = {
      'Content-Type': contentType,
      'X-Amz-Date': dateStr,
      Authorization: authorization,
    };
    if (sessionToken) headers['X-Amz-Security-Token'] = sessionToken;
    return headers;
  }

  _getSigningKey(secretKey, dateOnly, region, service) {
    const mac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
    return mac(
      mac(mac(mac(`AWS4${secretKey}`, dateOnly), region), service),
      'aws4_request'
    );
  }
}

module.exports = { AwsValidator };
