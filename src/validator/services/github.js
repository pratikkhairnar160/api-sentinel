/**
 * validator/services/github.js
 * Non-destructive GitHub token validation
 * Uses /user endpoint — read-only, no side effects
 */

'use strict';

const { BaseValidator } = require('../base');

class GithubValidator extends BaseValidator {
  constructor(options = {}) {
    super('github_pat', 'GitHub', options);
  }

  async probe(token) {
    // Safe read-only probe: /user returns authenticated user info
    const res = await this.http.get('https://api.github.com/user', {
      headers: {
        Authorization: `token ${token}`,
        Accept: 'application/vnd.github.v3+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (res.status === 200 && res.data?.login) {
      // Determine scopes from response header
      const scopesHeader = res.headers['x-oauth-scopes'] || '';
      const scopes = scopesHeader ? scopesHeader.split(',').map(s => s.trim()) : [];
      const hasRepoAccess = scopes.includes('repo') || scopes.includes('public_repo');
      const hasWriteAccess = scopes.some(s => ['repo', 'write:org', 'admin:org'].includes(s));

      return this._validResult({
        user:     res.data.login,
        userId:   res.data.id,
        scopes,
        hasRepoAccess,
        hasWriteAccess,
        rateLimit: {
          limit:     res.headers['x-ratelimit-limit'],
          remaining: res.headers['x-ratelimit-remaining'],
        },
        note: hasWriteAccess
          ? '⚠️ Token has write permissions — can modify repositories'
          : 'Token has read-only access',
      });
    }

    if (res.status === 401) {
      return this._invalidResult('Bad credentials — token is invalid or revoked');
    }

    if (res.status === 403) {
      if (res.headers['x-ratelimit-remaining'] === '0') {
        return this._rateLimitResult();
      }
      return this._restrictedResult({ note: 'Token valid but insufficient permissions for /user' });
    }

    return this._errorResult(`Unexpected status: ${res.status}`);
  }
}

module.exports = { GithubValidator };
