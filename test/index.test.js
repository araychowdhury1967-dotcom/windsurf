const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  detectSecurityChallenge,
  isJsonContentType,
  safeJsonParse
} = require('../lib/response-validator');

const {
  calculateDelay,
  isRetryable
} = require('../lib/retry-handler');

const {
  ERROR_DESCRIPTIONS,
  detectApiProxyError
} = require('../lib/mysql-connector');

const {
  SETTINGS_TABLE,
  buildConnectionConfig,
} = require('../lib/settings-manager');

// -- response-validator tests --

describe('detectSecurityChallenge', () => {
  it('returns false for valid JSON strings', () => {
    const result = detectSecurityChallenge('{"success": true}');
    assert.equal(result.isChallenge, false);
  });

  it('returns false for JSON arrays', () => {
    const result = detectSecurityChallenge('[1, 2, 3]');
    assert.equal(result.isChallenge, false);
  });

  it('returns false for empty string', () => {
    const result = detectSecurityChallenge('');
    assert.equal(result.isChallenge, false);
  });

  it('returns false for non-string input', () => {
    const result = detectSecurityChallenge(null);
    assert.equal(result.isChallenge, false);
  });

  it('detects Cloudflare challenge HTML', () => {
    const html = '<html><head><title>Attention Required! | Cloudflare</title></head></html>';
    const result = detectSecurityChallenge(html);
    assert.equal(result.isChallenge, true);
    assert.ok(result.matchedPattern, 'should have a matched pattern');
  });

  it('detects captcha challenge HTML', () => {
    const html = '<div class="captcha-container">Please verify you are human</div>';
    const result = detectSecurityChallenge(html);
    assert.equal(result.isChallenge, true);
    assert.equal(result.matchedPattern, 'captcha');
  });

  it('detects generic HTML as challenge', () => {
    const html = '<html><body>Some random page</body></html>';
    const result = detectSecurityChallenge(html);
    assert.equal(result.isChallenge, true);
    assert.equal(result.matchedPattern, 'generic-html');
  });

  it('detects Imunify360 challenge', () => {
    const html = '<div>Imunify360 protection active</div>';
    const result = detectSecurityChallenge(html);
    assert.equal(result.isChallenge, true);
    assert.ok(result.matchedPattern, 'should have a matched pattern');
  });

  it('detects access denied page', () => {
    const html = '<div><h1>Access Denied</h1></div>';
    const result = detectSecurityChallenge(html);
    assert.equal(result.isChallenge, true);
    assert.equal(result.matchedPattern, 'access.denied');
  });

  it('detects hCaptcha challenge', () => {
    const html = '<div class="hcaptcha-widget"></div>';
    const result = detectSecurityChallenge(html);
    assert.equal(result.isChallenge, true);
    assert.ok(result.matchedPattern, 'should have a matched pattern');
  });

  it('detects slowAES bot cookie challenge', () => {
    const html = '<html><body><script src="/aes.js"></script><script>slowAES.decrypt(c,2,a,b)</script></body></html>';
    const result = detectSecurityChallenge(html);
    assert.equal(result.isChallenge, true);
  });
});

describe('isJsonContentType', () => {
  it('returns true for application/json', () => {
    assert.equal(isJsonContentType('application/json'), true);
  });

  it('returns true for application/json with charset', () => {
    assert.equal(isJsonContentType('application/json; charset=utf-8'), true);
  });

  it('returns false for text/html', () => {
    assert.equal(isJsonContentType('text/html'), false);
  });

  it('returns false for null', () => {
    assert.equal(isJsonContentType(null), false);
  });

  it('returns false for undefined', () => {
    assert.equal(isJsonContentType(undefined), false);
  });
});

describe('safeJsonParse', () => {
  it('parses valid JSON successfully', () => {
    const result = safeJsonParse('{"key": "value"}', 'application/json');
    assert.equal(result.ok, true);
    assert.deepEqual(result.data, { key: 'value' });
    assert.equal(result.error, null);
  });

  it('returns error for HTML content-type with HTML body', () => {
    const result = safeJsonParse('<html></html>', 'text/html');
    assert.equal(result.ok, false);
    assert.ok(result.error.includes('Hosting security challenge'));
    assert.equal(result.details.isSecurityChallenge, true);
  });

  it('returns error for HTML body even without content-type', () => {
    const result = safeJsonParse('<html><body>Cloudflare check</body></html>');
    assert.equal(result.ok, false);
    assert.ok(result.error.includes('Hosting security challenge'));
  });

  it('returns parse error for invalid JSON', () => {
    const result = safeJsonParse('not json at all', 'application/json');
    assert.equal(result.ok, false);
    assert.ok(result.error.includes('JSON parse error'));
  });

  it('returns error for non-JSON content-type with non-HTML body', () => {
    const result = safeJsonParse('plain text', 'text/plain');
    assert.equal(result.ok, false);
    assert.ok(result.error.includes('Unexpected Content-Type'));
  });
});

// -- retry-handler tests --

describe('calculateDelay', () => {
  it('calculates base delay for first attempt', () => {
    const config = { baseDelayMs: 1000, backoffMultiplier: 2, maxDelayMs: 10000 };
    const delay = calculateDelay(0, config);
    // With jitter, should be within 750-1250
    assert.ok(delay >= 750 && delay <= 1250, `Delay ${delay} out of range`);
  });

  it('applies exponential backoff', () => {
    const config = { baseDelayMs: 1000, backoffMultiplier: 2, maxDelayMs: 10000 };
    const delay = calculateDelay(2, config);
    // Base would be 4000, with jitter 3000-5000
    assert.ok(delay >= 3000 && delay <= 5000, `Delay ${delay} out of range`);
  });

  it('caps at maxDelayMs', () => {
    const config = { baseDelayMs: 1000, backoffMultiplier: 2, maxDelayMs: 5000 };
    const delay = calculateDelay(10, config);
    // Capped at 5000, with jitter 3750-6250
    assert.ok(delay <= 6250, `Delay ${delay} exceeds cap with jitter`);
  });
});

describe('isRetryable', () => {
  it('returns true for ECONNRESET', () => {
    const err = new Error('Connection reset');
    err.code = 'ECONNRESET';
    assert.equal(isRetryable(err, ['ECONNRESET', 'ETIMEDOUT']), true);
  });

  it('returns false for ER_ACCESS_DENIED_ERROR', () => {
    const err = new Error('Access denied');
    err.code = 'ER_ACCESS_DENIED_ERROR';
    assert.equal(isRetryable(err, ['ECONNRESET', 'ETIMEDOUT']), false);
  });

  it('returns false for null error', () => {
    assert.equal(isRetryable(null, ['ECONNRESET']), false);
  });

  it('checks errno as fallback', () => {
    const err = new Error('test');
    err.errno = 'ETIMEDOUT';
    assert.equal(isRetryable(err, ['ETIMEDOUT']), true);
  });
});

// -- mysql-connector tests --

describe('ERROR_DESCRIPTIONS', () => {
  it('has description for ECONNREFUSED', () => {
    assert.ok(ERROR_DESCRIPTIONS.ECONNREFUSED);
    assert.ok(ERROR_DESCRIPTIONS.ECONNREFUSED.includes('Connection refused'));
  });

  it('has description for ER_ACCESS_DENIED_ERROR', () => {
    assert.ok(ERROR_DESCRIPTIONS.ER_ACCESS_DENIED_ERROR);
    assert.ok(ERROR_DESCRIPTIONS.ER_ACCESS_DENIED_ERROR.includes('Access denied'));
  });

  it('has description for ETIMEDOUT', () => {
    assert.ok(ERROR_DESCRIPTIONS.ETIMEDOUT);
    assert.ok(ERROR_DESCRIPTIONS.ETIMEDOUT.includes('timed out'));
  });

  it('has description for ENOTFOUND', () => {
    assert.ok(ERROR_DESCRIPTIONS.ENOTFOUND);
  });

  it('has description for ER_BAD_DB_ERROR', () => {
    assert.ok(ERROR_DESCRIPTIONS.ER_BAD_DB_ERROR);
  });
});

// -- detectApiProxyError tests --

describe('detectApiProxyError', () => {
  it('detects "Database API failed (500)" as an API proxy error', () => {
    const err = new Error('Database API failed (500)');
    const result = detectApiProxyError(err);
    assert.equal(result.isApiError, true);
    assert.equal(result.statusCode, 500);
  });

  it('detects "Internal Server Error" as an API proxy error', () => {
    const err = new Error('Internal Server Error');
    const result = detectApiProxyError(err);
    assert.equal(result.isApiError, true);
  });

  it('detects "Bad Gateway" as an API proxy error', () => {
    const err = new Error('Bad Gateway');
    const result = detectApiProxyError(err);
    assert.equal(result.isApiError, true);
  });

  it('detects "API error (502)" as an API proxy error with status code', () => {
    const err = new Error('API error (502)');
    const result = detectApiProxyError(err);
    assert.equal(result.isApiError, true);
    assert.equal(result.statusCode, 502);
  });

  it('returns false for standard MySQL errors', () => {
    const err = new Error('Access denied for user');
    err.code = 'ER_ACCESS_DENIED_ERROR';
    const result = detectApiProxyError(err);
    assert.equal(result.isApiError, false);
    assert.equal(result.statusCode, null);
  });

  it('returns false for connection errors', () => {
    const err = new Error('connect ECONNREFUSED 127.0.0.1:3306');
    err.code = 'ECONNREFUSED';
    const result = detectApiProxyError(err);
    assert.equal(result.isApiError, false);
  });

  it('uses sqlMessage when available', () => {
    const err = new Error('generic');
    err.sqlMessage = 'API failed (503)';
    const result = detectApiProxyError(err);
    assert.equal(result.isApiError, true);
    assert.equal(result.statusCode, 503);
  });
});

// -- settings-manager tests --

describe('SETTINGS_TABLE', () => {
  it('is a non-empty string', () => {
    assert.equal(typeof SETTINGS_TABLE, 'string');
    assert.ok(SETTINGS_TABLE.length > 0);
  });
});

describe('buildConnectionConfig', () => {
  it('builds config with required fields', () => {
    const config = buildConnectionConfig({
      host: 'myhost',
      user: 'myuser',
      password: 'mypass'
    });
    assert.equal(config.host, 'myhost');
    assert.equal(config.user, 'myuser');
    assert.equal(config.password, 'mypass');
    assert.equal(config.port, 3306);
  });

  it('uses provided port', () => {
    const config = buildConnectionConfig({
      host: 'h',
      user: 'u',
      password: 'p',
      port: 3307
    });
    assert.equal(config.port, 3307);
  });

  it('includes database when provided', () => {
    const config = buildConnectionConfig({
      host: 'h',
      user: 'u',
      password: 'p',
      database: 'testdb'
    });
    assert.equal(config.database, 'testdb');
  });

  it('does not include database when not provided', () => {
    const config = buildConnectionConfig({
      host: 'h',
      user: 'u',
      password: 'p'
    });
    assert.equal(config.database, undefined);
  });

  it('adds ssl config when ssl is true', () => {
    const config = buildConnectionConfig({
      host: 'h',
      user: 'u',
      password: 'p',
      ssl: true
    });
    assert.ok(config.ssl);
    assert.equal(config.ssl.rejectUnauthorized, true);
  });

  it('does not add ssl config when ssl is false', () => {
    const config = buildConnectionConfig({
      host: 'h',
      user: 'u',
      password: 'p',
      ssl: false
    });
    assert.equal(config.ssl, undefined);
  });
});

describe('saveSettings validation', () => {
  const { saveSettings } = require('../lib/settings-manager');

  it('returns error when database is missing', async () => {
    const result = await saveSettings(
      { host: 'h', user: 'u', password: 'p' },
      [{ key: 'k', value: 'v' }]
    );
    assert.equal(result.success, false);
    assert.ok(result.message.includes('database'));
  });

  it('returns error when records array is empty', async () => {
    const result = await saveSettings(
      { host: 'h', user: 'u', password: 'p', database: 'db' },
      []
    );
    assert.equal(result.success, false);
    assert.ok(result.message.includes('record'));
  });

  it('returns error when records is not an array', async () => {
    const result = await saveSettings(
      { host: 'h', user: 'u', password: 'p', database: 'db' },
      'not-array'
    );
    assert.equal(result.success, false);
  });

  it('returns error when a record has no key', async () => {
    const result = await saveSettings(
      { host: 'h', user: 'u', password: 'p', database: 'db' },
      [{ key: '', value: 'v' }]
    );
    assert.equal(result.success, false);
    assert.ok(result.message.includes('key'));
  });
});

describe('getSettings validation', () => {
  const { getSettings } = require('../lib/settings-manager');

  it('returns error when database is missing', async () => {
    const result = await getSettings({ host: 'h', user: 'u', password: 'p' });
    assert.equal(result.success, false);
    assert.ok(result.message.includes('database'));
  });
});

describe('deleteSettings validation', () => {
  const { deleteSettings } = require('../lib/settings-manager');

  it('returns error when database is missing', async () => {
    const result = await deleteSettings(
      { host: 'h', user: 'u', password: 'p' },
      ['k']
    );
    assert.equal(result.success, false);
    assert.ok(result.message.includes('database'));
  });

  it('returns error when keys array is empty', async () => {
    const result = await deleteSettings(
      { host: 'h', user: 'u', password: 'p', database: 'db' },
      []
    );
    assert.equal(result.success, false);
    assert.ok(result.message.includes('key'));
  });
});
