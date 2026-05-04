/**
 * patterns.js — Curated regex patterns for API key / secret detection
 * Covers major cloud providers, SaaS platforms, and generic token formats
 */

'use strict';

/**
 * Each pattern entry:
 *  name       — human-readable service name
 *  id         — unique key for the service
 *  regex      — RegExp to match the key
 *  confidence — 'high' | 'medium' | 'low'
 *  riskLevel  — 'critical' | 'high' | 'medium' | 'low'
 *  docs       — validation docs reference
 */
const PATTERNS = [
  // ─── AWS ──────────────────────────────────────────────────────────────────
  {
    id: 'aws_access_key',
    name: 'AWS Access Key ID',
    regex: /\b(AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}\b/g,
    confidence: 'high',
    riskLevel: 'critical',
    docs: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
  },
  {
    id: 'aws_secret_key',
    name: 'AWS Secret Access Key',
    regex: /(?:aws_secret|secret_key|SecretAccessKey)['":\s=]+([A-Za-z0-9/+]{40})/gi,
    confidence: 'high',
    riskLevel: 'critical',
    docs: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
  },

  // ─── Google ───────────────────────────────────────────────────────────────
  {
    id: 'google_api_key',
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://cloud.google.com/docs/authentication/api-keys',
  },
  {
    id: 'google_oauth',
    name: 'Google OAuth Client ID',
    regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    confidence: 'high',
    riskLevel: 'medium',
    docs: 'https://developers.google.com/identity/protocols/oauth2',
  },
  {
    id: 'google_service_account',
    name: 'Google Service Account Key',
    regex: /"type"\s*:\s*"service_account"/g,
    confidence: 'high',
    riskLevel: 'critical',
    docs: 'https://cloud.google.com/iam/docs/service-account-keys',
  },

  // ─── Firebase ─────────────────────────────────────────────────────────────
  {
    id: 'firebase_key',
    name: 'Firebase API Key',
    regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://firebase.google.com/docs/projects/api-keys',
  },

  // ─── Stripe ───────────────────────────────────────────────────────────────
  {
    id: 'stripe_live_secret',
    name: 'Stripe Live Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24,99}/g,
    confidence: 'high',
    riskLevel: 'critical',
    docs: 'https://stripe.com/docs/keys',
  },
  {
    id: 'stripe_test_secret',
    name: 'Stripe Test Secret Key',
    regex: /sk_test_[0-9a-zA-Z]{24,99}/g,
    confidence: 'high',
    riskLevel: 'medium',
    docs: 'https://stripe.com/docs/keys',
  },
  {
    id: 'stripe_publishable',
    name: 'Stripe Publishable Key',
    regex: /pk_(live|test)_[0-9a-zA-Z]{24,99}/g,
    confidence: 'high',
    riskLevel: 'low',
    docs: 'https://stripe.com/docs/keys',
  },

  // ─── GitHub ───────────────────────────────────────────────────────────────
  {
    id: 'github_pat',
    name: 'GitHub Personal Access Token',
    regex: /ghp_[A-Za-z0-9]{36}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github',
  },
  {
    id: 'github_oauth',
    name: 'GitHub OAuth Token',
    regex: /gho_[A-Za-z0-9]{36}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps',
  },
  {
    id: 'github_app_token',
    name: 'GitHub App Installation Token',
    regex: /ghs_[A-Za-z0-9]{36}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://docs.github.com/en/apps',
  },

  // ─── Slack ────────────────────────────────────────────────────────────────
  {
    id: 'slack_bot_token',
    name: 'Slack Bot Token',
    regex: /xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://api.slack.com/authentication/token-types',
  },
  {
    id: 'slack_user_token',
    name: 'Slack User Token',
    regex: /xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{32}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://api.slack.com/authentication/token-types',
  },
  {
    id: 'slack_webhook',
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://api.slack.com/messaging/webhooks',
  },

  // ─── Twilio ───────────────────────────────────────────────────────────────
  {
    id: 'twilio_account_sid',
    name: 'Twilio Account SID',
    regex: /AC[a-z0-9]{32}/g,
    confidence: 'medium',
    riskLevel: 'high',
    docs: 'https://www.twilio.com/docs/glossary/what-is-a-sid',
  },
  {
    id: 'twilio_auth_token',
    name: 'Twilio Auth Token',
    regex: /(?:twilio|auth_token|authtoken)['":\s=]+([a-z0-9]{32})/gi,
    confidence: 'medium',
    riskLevel: 'high',
    docs: 'https://www.twilio.com/docs/glossary/what-is-an-authentication-token',
  },

  // ─── SendGrid ─────────────────────────────────────────────────────────────
  {
    id: 'sendgrid_api_key',
    name: 'SendGrid API Key',
    regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://docs.sendgrid.com/ui/account-and-settings/api-keys',
  },

  // ─── Mailgun ──────────────────────────────────────────────────────────────
  {
    id: 'mailgun_api_key',
    name: 'Mailgun API Key',
    regex: /key-[0-9a-zA-Z]{32}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://documentation.mailgun.com/en/latest/api-intro.html',
  },

  // ─── Shopify ──────────────────────────────────────────────────────────────
  {
    id: 'shopify_token',
    name: 'Shopify Access Token',
    regex: /shpat_[a-fA-F0-9]{32}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://shopify.dev/docs/apps/auth/access-token-types',
  },
  {
    id: 'shopify_shared_secret',
    name: 'Shopify Shared Secret',
    regex: /shpss_[a-fA-F0-9]{32}/g,
    confidence: 'high',
    riskLevel: 'high',
    docs: 'https://shopify.dev/docs/apps/auth/access-token-types',
  },

  // ─── HubSpot ──────────────────────────────────────────────────────────────
  {
    id: 'hubspot_api_key',
    name: 'HubSpot API Key',
    regex: /(?:hubspot|hapikey)['":\s=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi,
    confidence: 'medium',
    riskLevel: 'high',
    docs: 'https://developers.hubspot.com/docs/api/overview',
  },

  // ─── JWT Tokens ───────────────────────────────────────────────────────────
  {
    id: 'jwt_token',
    name: 'JWT Token',
    regex: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*/g,
    confidence: 'medium',
    riskLevel: 'medium',
    docs: 'https://jwt.io/introduction',
  },

  // ─── Generic secrets ──────────────────────────────────────────────────────
  {
    id: 'generic_api_key',
    name: 'Generic API Key Assignment',
    regex: /(?:api_key|apikey|api-key|access_key|secret_key)['":\s=]+['"]([A-Za-z0-9_\-]{16,64})['"]/gi,
    confidence: 'low',
    riskLevel: 'medium',
    docs: null,
  },
  {
    id: 'generic_bearer_token',
    name: 'Bearer Token (HTTP Header)',
    regex: /Bearer\s+([A-Za-z0-9\-._~+/]+=*)/g,
    confidence: 'medium',
    riskLevel: 'medium',
    docs: 'https://datatracker.ietf.org/doc/html/rfc6750',
  },
  {
    id: 'generic_password',
    name: 'Hardcoded Password',
    regex: /(?:password|passwd|pwd)['":\s=]+['"]([^'"]{8,64})['"]/gi,
    confidence: 'low',
    riskLevel: 'high',
    docs: null,
  },

  // ─── Database connection strings ──────────────────────────────────────────
  {
    id: 'mongodb_uri',
    name: 'MongoDB Connection URI',
    regex: /mongodb(?:\+srv)?:\/\/[^'"\s]+/gi,
    confidence: 'high',
    riskLevel: 'critical',
    docs: 'https://www.mongodb.com/docs/manual/reference/connection-string/',
  },
  {
    id: 'postgres_uri',
    name: 'PostgreSQL Connection URI',
    regex: /postgres(?:ql)?:\/\/[^'"\s]+/gi,
    confidence: 'high',
    riskLevel: 'critical',
    docs: 'https://www.postgresql.org/docs/current/libpq-connect.html',
  },
  {
    id: 'mysql_uri',
    name: 'MySQL Connection URI',
    regex: /mysql:\/\/[^'"\s]+/gi,
    confidence: 'high',
    riskLevel: 'critical',
    docs: 'https://dev.mysql.com/doc/connector-j/8.0/en/connector-j-reference-jdbc-url-format.html',
  },

  // ─── Azure ────────────────────────────────────────────────────────────────
  {
    id: 'azure_storage_key',
    name: 'Azure Storage Account Key',
    regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/g,
    confidence: 'high',
    riskLevel: 'critical',
    docs: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage',
  },
];

module.exports = { PATTERNS };
