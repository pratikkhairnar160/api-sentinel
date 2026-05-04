/**
 * validator/services/slack.js
 * Non-destructive Slack token validation
 * Uses auth.test — read-only, no side effects
 */
'use strict';

const { BaseValidator } = require('../base');

class SlackValidator extends BaseValidator {
  constructor(options = {}) {
    super('slack_bot_token', 'Slack', options);
  }

  async probe(token) {
    // auth.test is the canonical Slack auth check — purely read-only
    const res = await this.http.post('https://slack.com/api/auth.test', null, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    });

    const body = res.data;
    if (body?.ok) {
      return this._validResult({
        team:     body.team,
        user:     body.user,
        teamId:   body.team_id,
        userId:   body.user_id,
        botId:    body.bot_id,
        isBot:    !!body.bot_id,
        note: body.bot_id
          ? `Bot token for workspace: ${body.team}`
          : `User token for: ${body.user} @ ${body.team}`,
      });
    }

    const err = body?.error || 'unknown_error';
    if (['invalid_auth', 'not_authed', 'token_revoked'].includes(err)) {
      return this._invalidResult(`Token rejected: ${err}`);
    }
    if (err === 'ratelimited') return this._rateLimitResult();

    return this._errorResult(`Slack API error: ${err}`);
  }
}

/**
 * validator/services/sendgrid.js
 * Non-destructive SendGrid validation using scopes endpoint
 */
class SendGridValidator extends BaseValidator {
  constructor(options = {}) {
    super('sendgrid_api_key', 'SendGrid', options);
  }

  async probe(key) {
    // /v3/scopes returns the permissions of the key — purely read-only
    const res = await this.http.get('https://api.sendgrid.com/v3/scopes', {
      headers: { Authorization: `Bearer ${key}` },
    });

    if (res.status === 200 && res.data?.scopes) {
      const scopes    = res.data.scopes || [];
      const canSend   = scopes.includes('mail.send');
      const hasAdmin  = scopes.some(s => s.includes('admin'));
      return this._validResult({
        scopes,
        canSendEmail: canSend,
        isAdmin:      hasAdmin,
        scopeCount:   scopes.length,
        note: canSend
          ? '⚠️ Key can send emails — phishing/spam risk'
          : 'Key has limited send permissions',
      });
    }

    if (res.status === 401 || res.status === 403) {
      return this._invalidResult(`Authentication failed (${res.status})`);
    }
    if (res.status === 429) return this._rateLimitResult();

    return this._errorResult(`Unexpected status: ${res.status}`);
  }
}

module.exports = { SlackValidator, SendGridValidator };
