/**
 * validator/index.js
 * Dispatches findings to the appropriate service validator
 * Enforces rate limiting and non-destructive constraints
 */

'use strict';

const PQueue = require('p-queue').default;
const { GoogleValidator }  = require('./services/google');
const { AwsValidator }     = require('./services/aws');
const { StripeValidator }  = require('./services/stripe');
const { GithubValidator }  = require('./services/github');
const { GenericValidator } = require('./services/generic');
const logger = require('../utils/logger');

const { TwilioValidator, ShopifyValidator, MailgunValidator } = require('./services/twilio');
const { SlackValidator, SendGridValidator } = require('./services/slack');

// Map pattern IDs → validator classes
const VALIDATOR_MAP = {
  google_api_key:        GoogleValidator,
  google_oauth:          GoogleValidator,
  google_service_account: GoogleValidator,
  firebase_key:          GoogleValidator,
  aws_access_key:        AwsValidator,
  aws_secret_key:        AwsValidator,
  stripe_live_secret:    StripeValidator,
  stripe_test_secret:    StripeValidator,
  stripe_publishable:    StripeValidator,
  github_pat:            GithubValidator,
  github_oauth:          GithubValidator,
  github_app_token:      GithubValidator,
  slack_bot_token:       SlackValidator,
  slack_user_token:      SlackValidator,
  sendgrid_api_key:      SendGridValidator,
  mailgun_api_key:       MailgunValidator,
  twilio_account_sid:    TwilioValidator,
  shopify_token:         ShopifyValidator,
  jwt_token:             GenericValidator,
  mongodb_uri:           GenericValidator,   // Never probe DB URIs live
  postgres_uri:          GenericValidator,
  mysql_uri:             GenericValidator,
  azure_storage_key:     GenericValidator,
  generic_api_key:       GenericValidator,
  generic_bearer_token:  GenericValidator,
  generic_password:      GenericValidator,
  entropy_heuristic:     GenericValidator,
};

// Pattern IDs that should NEVER be validated live
const SKIP_LIVE_VALIDATION = new Set([
  'mongodb_uri', 'postgres_uri', 'mysql_uri',
  'azure_storage_key', 'generic_password',
]);

const DEFAULT_OPTIONS = {
  concurrency: 3,    // Max simultaneous validation requests
  delayMs: 500,      // Polite delay between validations
  skipValidation: false,
};

class ValidatorOrchestrator {
  constructor(options = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.queue = new PQueue({ concurrency: this.options.concurrency });
    this.validators = {}; // Cached validator instances
  }

  /**
   * Get or create a validator for a given pattern ID
   */
  _getValidator(patternId) {
    if (!this.validators[patternId]) {
      const ValidatorClass = VALIDATOR_MAP[patternId] || GenericValidator;
      this.validators[patternId] = new ValidatorClass();
    }
    return this.validators[patternId];
  }

  /**
   * Validate a single finding
   * @param {EnrichedFinding} finding
   * @param {function} [onResult] callback for real-time GUI updates
   * @returns {Promise<EnrichedFinding>}
   */
  async validateOne(finding, onResult = null) {
    if (this.options.skipValidation) {
      finding.validationResult = { status: 'skipped', message: 'Validation disabled by user' };
      return finding;
    }

    const validator = this._getValidator(finding.patternId);

    // For AWS, we need key pair — try to correlate access key + secret
    let keyToValidate = finding.value;
    if (finding.patternId === 'aws_access_key') {
      // Will validate ID only (secret correlation done during scan if found in same context)
      keyToValidate = finding.awsKeyPair || { accessKeyId: finding.value, secretAccessKey: null };
    }

    try {
      await this._delay(this.options.delayMs);
      const result = await validator.validate(keyToValidate);
      finding.validationResult = result;
      finding.validated = true;
      if (onResult) onResult(finding);
      logger.debug(`[Validator] ${finding.patternId} → ${result.status}`);
    } catch (err) {
      finding.validationResult = { status: 'error', message: err.message };
      finding.validated = true;
    }

    return finding;
  }

  /**
   * Validate all findings with controlled concurrency
   * @param {EnrichedFinding[]} findings
   * @param {function} [onResult] real-time callback
   * @returns {Promise<EnrichedFinding[]>}
   */
  async validateAll(findings, onResult = null) {
    logger.info(`[Validator] Validating ${findings.length} findings...`);

    const tasks = findings.map(finding =>
      this.queue.add(() => this.validateOne(finding, onResult))
    );

    await Promise.allSettled(tasks);
    await this.queue.onIdle();

    const stats = this._summarizeResults(findings);
    logger.info(`[Validator] Done — valid:${stats.valid} invalid:${stats.invalid} error:${stats.error}`);
    return findings;
  }

  _summarizeResults(findings) {
    return findings.reduce((acc, f) => {
      const s = f.validationResult?.status || 'unknown';
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {});
  }

  _delay(ms) {
    return new Promise(r => setTimeout(r, ms));
  }
}

module.exports = { ValidatorOrchestrator };
