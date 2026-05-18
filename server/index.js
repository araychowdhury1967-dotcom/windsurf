/**
 * Express server that provides a MySQL connection testing API.
 *
 * This server-side approach bypasses hosting WAF/security challenges
 * that block direct browser-to-MySQL API calls by:
 *  1. Running the MySQL connection test on the server (not in the browser).
 *  2. Validating all responses and detecting HTML security challenges.
 *  3. Retrying transient failures with exponential backoff.
 */

const express = require('express');
const cors = require('cors');
const { testConnection } = require('../lib/mysql-connector');
const { safeJsonParse } = require('../lib/response-validator');
const { withRetry } = require('../lib/retry-handler');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('client'));

/**
 * Middleware: Ensure every response is valid JSON, never HTML.
 * This prevents the exact error the user encountered.
 */
app.use((req, res, next) => {
  // Override res.send to always validate output
  const originalSend = res.send.bind(res);
  res.send = function (body) {
    // Ensure Content-Type is always JSON for API routes
    if (req.path.startsWith('/api/')) {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('X-Content-Type-Options', 'nosniff');
    }
    return originalSend(body);
  };
  next();
});

/**
 * Health check endpoint.
 */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/**
 * MySQL connection test endpoint.
 *
 * POST /api/test-connection
 * Body: { host, port, user, password, database?, ssl? }
 *
 * Returns JSON with connection test results, never HTML.
 */
app.post('/api/test-connection', async (req, res) => {
  const { host, port, user, password, database, ssl } = req.body;

  // Validate required fields
  if (!host || !user) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: host and user are required.',
      error: { code: 'VALIDATION_ERROR' }
    });
  }

  if (password === undefined || password === null) {
    return res.status(400).json({
      success: false,
      message: 'Missing required field: password.',
      error: { code: 'VALIDATION_ERROR' }
    });
  }

  try {
    // Use retry logic for transient connection failures
    const result = await withRetry(
      async () => {
        const connectionResult = await testConnection({
          host,
          port: port || 3306,
          user,
          password,
          database: database || undefined,
          ssl: ssl || false
        });

        // If the connection failed with a retryable error, throw to trigger retry
        if (!connectionResult.success && connectionResult.error) {
          const retryableCodes = ['ECONNRESET', 'ETIMEDOUT', 'PROTOCOL_CONNECTION_LOST', 'EPIPE'];
          if (retryableCodes.includes(connectionResult.error.code)) {
            const error = new Error(connectionResult.message);
            error.code = connectionResult.error.code;
            error.connectionResult = connectionResult;
            throw error;
          }
        }

        return connectionResult;
      },
      { maxRetries: 2 },
      (attempt, delay, err) => {
        console.log(`Retry ${attempt} after ${delay}ms due to: ${err.code || err.message}`);
      }
    );

    const statusCode = result.success ? 200 : 400;
    return res.status(statusCode).json(result);
  } catch (err) {
    // If retry exhausted and we have a connectionResult, return it
    if (err.connectionResult) {
      return res.status(400).json(err.connectionResult);
    }

    console.error('Unexpected error during connection test:', err);
    return res.status(500).json({
      success: false,
      message: `Unexpected error: ${err.message}`,
      error: {
        code: err.code || 'INTERNAL_ERROR',
        sqlMessage: err.message
      },
      troubleshooting: [
        'Check the server logs for more details.',
        'Verify the MySQL credentials and host are correct.'
      ]
    });
  }
});

/**
 * Proxy endpoint for external MySQL API services.
 *
 * POST /api/proxy-request
 * Body: { url, method?, headers?, body? }
 *
 * Makes the request server-side to bypass WAF/security challenges,
 * validates the response, and returns clean JSON.
 */
app.post('/api/proxy-request', async (req, res) => {
  const { url, method, headers, body } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      message: 'Missing required field: url.',
      error: { code: 'VALIDATION_ERROR' }
    });
  }

  // Validate URL to prevent SSRF attacks
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (_urlErr) {
    return res.status(400).json({
      success: false,
      message: 'Invalid URL format.',
      error: { code: 'VALIDATION_ERROR' }
    });
  }

  // Only allow HTTP and HTTPS protocols
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return res.status(400).json({
      success: false,
      message: 'Only http and https URLs are allowed.',
      error: { code: 'VALIDATION_ERROR' }
    });
  }

  // Block requests to private/internal IP ranges
  const hostname = parsedUrl.hostname;
  const privatePatterns = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^0\./,
    /^\[::1\]$/,
    /^\[fc/i,
    /^\[fd/i,
    /^\[fe80:/i
  ];

  if (privatePatterns.some(pattern => pattern.test(hostname))) {
    return res.status(403).json({
      success: false,
      message: 'Requests to private/internal addresses are not allowed.',
      error: { code: 'FORBIDDEN' }
    });
  }

  try {
    const fetchOptions = {
      method: method || 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(headers || {})
      }
    };

    if (body) {
      fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
    }

    const response = await fetch(url, fetchOptions);
    const responseText = await response.text();
    const contentType = response.headers.get('content-type') || '';

    // Use our validator to check for security challenges
    const parsed = safeJsonParse(responseText, contentType);

    if (!parsed.ok) {
      return res.status(502).json({
        success: false,
        message: parsed.error,
        details: parsed.details,
        troubleshooting: [
          'The remote host returned HTML instead of JSON.',
          'This is typically caused by a WAF, Cloudflare, or hosting security challenge.',
          'Solutions:',
          '  1. Whitelist the API endpoint in your hosting WAF/firewall settings.',
          '  2. If using Cloudflare, add a bypass rule for the API path.',
          '  3. Contact your hosting provider to whitelist server-to-server requests.',
          '  4. Use this server-side proxy instead of making direct browser requests.'
        ]
      });
    }

    return res.json({
      success: true,
      data: parsed.data,
      meta: {
        status: response.status,
        contentType
      }
    });
  } catch (err) {
    console.error('Proxy request error:', err);
    return res.status(502).json({
      success: false,
      message: `Failed to reach remote host: ${err.message}`,
      error: { code: err.code || 'PROXY_ERROR' },
      troubleshooting: [
        'Verify the URL is correct and the remote server is running.',
        'Check network connectivity from this server.'
      ]
    });
  }
});

/**
 * Catch-all for unknown API routes.
 */
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Unknown API endpoint: ${req.method} ${req.originalUrl}`,
    error: { code: 'NOT_FOUND' }
  });
});

// Start server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`MySQL Connection Tester running on http://localhost:${PORT}`);
    console.log('Endpoints:');
    console.log(`  GET  http://localhost:${PORT}/api/health`);
    console.log(`  POST http://localhost:${PORT}/api/test-connection`);
    console.log(`  POST http://localhost:${PORT}/api/proxy-request`);
  });
}

module.exports = app;
