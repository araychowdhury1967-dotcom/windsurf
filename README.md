# MySQL Connection Tester

A robust MySQL connection testing tool that handles hosting security challenges (WAF/Cloudflare/Imunify360) which return HTML instead of JSON.

## Problem

When testing MySQL connections from browser-based tools, hosting security layers (Cloudflare, Imunify360, ModSecurity, etc.) can intercept AJAX requests and return HTML challenge pages instead of the expected JSON response, causing errors like:

```
MySQL connection test failed: Error: Hosting security challenge returned HTML instead of JSON.
Refresh the page, then retry. If it repeats, this host is blocking API requests.
```

## Solution

This tool solves the problem by:

1. **Server-side MySQL connections** - The connection is made from the Node.js server directly, bypassing browser-level WAF interception.
2. **Response validation** - Every response is validated for Content-Type and checked against known security challenge patterns before JSON parsing.
3. **Retry with backoff** - Transient failures are automatically retried with exponential backoff and jitter.
4. **Proxy endpoint** - A server-side proxy endpoint for forwarding requests to external MySQL APIs, bypassing WAF restrictions.
5. **Detailed troubleshooting** - Every error includes actionable troubleshooting steps.

## Setup

```bash
npm install
npm start
```

Open `http://localhost:3000` in your browser.

## API Endpoints

### `GET /api/health`
Health check.

### `POST /api/test-connection`
Test a MySQL connection.

```json
{
  "host": "localhost",
  "port": 3306,
  "user": "root",
  "password": "mypassword",
  "database": "mydb",
  "ssl": false
}
```

### `POST /api/proxy-request`
Proxy an external API request server-side to bypass WAF/security challenges.

```json
{
  "url": "https://your-hosting-api.com/mysql/test",
  "method": "POST",
  "headers": {},
  "body": {}
}
```

## Running Tests

```bash
npm test
```

## Architecture

```
windsurf/
  client/         - Browser frontend (static HTML)
  server/         - Express API server
  lib/
    mysql-connector.js     - MySQL connection logic with error mapping
    response-validator.js  - HTML security challenge detection
    retry-handler.js       - Exponential backoff retry logic
  test/           - Unit tests
```

## Security Challenge Detection

The response validator detects these common hosting security patterns:
- Cloudflare challenges and Turnstile
- hCaptcha / reCAPTCHA pages
- Imunify360 security checks
- ModSecurity blocks
- Generic access denied / forbidden pages
- slowAES bot cookie challenges (common on free hosting)
