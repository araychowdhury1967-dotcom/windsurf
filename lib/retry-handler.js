/**
 * Retry logic with exponential backoff for handling transient failures,
 * including hosting security challenges that may resolve after a delay.
 */

/**
 * Default retry configuration.
 */
const DEFAULT_RETRY_CONFIG = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 10000,
  backoffMultiplier: 2,
  retryableErrors: [
    'ECONNRESET',
    'ETIMEDOUT',
    'ECONNREFUSED',
    'PROTOCOL_CONNECTION_LOST',
    'EPIPE',
    'EAI_AGAIN'
  ]
};

/**
 * Sleep for the specified duration.
 *
 * @param {number} ms - Milliseconds to sleep.
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Calculate delay with exponential backoff and jitter.
 *
 * @param {number} attempt - Current attempt number (0-based).
 * @param {object} config - Retry configuration.
 * @returns {number} Delay in milliseconds.
 */
function calculateDelay(attempt, config) {
  const delay = Math.min(
    config.baseDelayMs * Math.pow(config.backoffMultiplier, attempt),
    config.maxDelayMs
  );
  // Add jitter: +/- 25% randomness
  const jitter = delay * 0.25 * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(delay + jitter));
}

/**
 * Determine whether an error is retryable.
 *
 * @param {Error} err - The error to check.
 * @param {string[]} retryableErrors - List of retryable error codes.
 * @returns {boolean}
 */
function isRetryable(err, retryableErrors) {
  if (!err) return false;
  if (retryableErrors.includes(err.code)) return true;
  if (err.errno && retryableErrors.includes(err.errno)) return true;
  return false;
}

/**
 * Execute an async function with retry logic.
 *
 * @param {Function} fn - Async function to execute.
 * @param {object} [options] - Override default retry config.
 * @param {Function} [onRetry] - Callback invoked before each retry: (attempt, delay, error).
 * @returns {Promise<any>} Result of the function.
 */
async function withRetry(fn, options, onRetry) {
  const config = { ...DEFAULT_RETRY_CONFIG, ...options };
  let lastError = null;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastError = err;

      if (attempt >= config.maxRetries) {
        break;
      }

      if (!isRetryable(err, config.retryableErrors)) {
        break;
      }

      const delay = calculateDelay(attempt, config);
      if (typeof onRetry === 'function') {
        try {
          onRetry(attempt + 1, delay, err);
        } catch (_callbackErr) {
          // Prevent callback errors from aborting the retry loop
        }
      }
      await sleep(delay);
    }
  }

  throw lastError;
}

module.exports = {
  DEFAULT_RETRY_CONFIG,
  sleep,
  calculateDelay,
  isRetryable,
  withRetry
};
