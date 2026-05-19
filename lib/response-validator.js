/**
 * Response validation utilities for detecting and handling hosting security
 * challenges (WAF/Cloudflare/Imunify360) that return HTML instead of JSON.
 */

/**
 * Common patterns found in hosting security challenge HTML responses.
 */
const SECURITY_CHALLENGE_PATTERNS = [
  /cloudflare/i,
  /captcha/i,
  /challenge-platform/i,
  /security.check/i,
  /aes\.js/i,
  /slowAES/i,
  /imunify360/i,
  /mod_security/i,
  /blocked/i,
  /forbidden/i,
  /access.denied/i,
  /bot.detection/i,
  /ddos.protection/i,
  /ray.id/i,
  /cf-browser-verification/i,
  /jschl-answer/i,
  /__cf_chl_jschl_tk__/i,
  /turnstile/i,
  /hcaptcha/i,
  /recaptcha/i
];

/**
 * Checks whether a response body looks like an HTML security challenge
 * rather than valid JSON.
 *
 * @param {string} body - The raw response body text.
 * @returns {{ isChallenge: boolean, matchedPattern: string|null }}
 */
function detectSecurityChallenge(body) {
  if (typeof body !== 'string' || body.length === 0) {
    return { isChallenge: false, matchedPattern: null };
  }

  const trimmed = body.trim();

  // If it starts with '{' or '[' it is likely JSON, not HTML
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return { isChallenge: false, matchedPattern: null };
  }

  // If it starts with '<' it is almost certainly HTML
  if (trimmed.startsWith('<')) {
    for (const pattern of SECURITY_CHALLENGE_PATTERNS) {
      if (pattern.test(trimmed)) {
        return { isChallenge: true, matchedPattern: pattern.source };
      }
    }
    // HTML but not a recognized security challenge — still not valid JSON
    return { isChallenge: true, matchedPattern: 'generic-html' };
  }

  return { isChallenge: false, matchedPattern: null };
}

/**
 * Validates that a Content-Type header indicates JSON.
 *
 * @param {string} contentType - The Content-Type header value.
 * @returns {boolean}
 */
function isJsonContentType(contentType) {
  if (typeof contentType !== 'string') {
    return false;
  }
  return contentType.toLowerCase().includes('application/json');
}

/**
 * Safely parses a JSON response, returning a structured error when the
 * response is HTML (e.g. a hosting security challenge).
 *
 * @param {string} body - Raw response body.
 * @param {string} [contentType] - Optional Content-Type header.
 * @returns {{ ok: boolean, data: any, error: string|null, details: object|null }}
 */
function safeJsonParse(body, contentType) {
  // Check content-type first
  if (contentType && !isJsonContentType(contentType)) {
    const challenge = detectSecurityChallenge(body);
    return {
      ok: false,
      data: null,
      error: challenge.isChallenge
        ? 'Hosting security challenge returned HTML instead of JSON. Refresh the page, then retry. If it repeats, this host is blocking API requests.'
        : `Unexpected Content-Type: ${contentType}. Expected application/json.`,
      details: {
        contentType,
        isSecurityChallenge: challenge.isChallenge,
        matchedPattern: challenge.matchedPattern,
        bodyPreview: typeof body === 'string' ? body.substring(0, 200) : null
      }
    };
  }

  // Check body for HTML even if content-type is missing
  const challenge = detectSecurityChallenge(body);
  if (challenge.isChallenge) {
    return {
      ok: false,
      data: null,
      error: 'Hosting security challenge returned HTML instead of JSON. Refresh the page, then retry. If it repeats, this host is blocking API requests.',
      details: {
        contentType: contentType || 'not provided',
        isSecurityChallenge: true,
        matchedPattern: challenge.matchedPattern,
        bodyPreview: typeof body === 'string' ? body.substring(0, 200) : null
      }
    };
  }

  // Attempt JSON parse
  try {
    const data = JSON.parse(body);
    return { ok: true, data, error: null, details: null };
  } catch (parseError) {
    return {
      ok: false,
      data: null,
      error: `JSON parse error: ${parseError.message}`,
      details: {
        contentType: contentType || 'not provided',
        isSecurityChallenge: false,
        matchedPattern: null,
        bodyPreview: typeof body === 'string' ? body.substring(0, 200) : null
      }
    };
  }
}

module.exports = {
  SECURITY_CHALLENGE_PATTERNS,
  detectSecurityChallenge,
  isJsonContentType,
  safeJsonParse
};
