/**
 * MySQL connection module that runs server-side, bypassing hosting
 * WAF/security challenges that block browser-based API requests.
 */

const mysql = require('mysql2/promise');

/**
 * Default connection options.
 */
const DEFAULT_OPTIONS = {
  connectTimeout: 10000,
  waitForConnections: true,
  connectionLimit: 1,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
};

/**
 * Error codes mapped to human-readable descriptions.
 */
const ERROR_DESCRIPTIONS = {
  ECONNREFUSED: 'Connection refused. Verify the host and port are correct and the MySQL server is running.',
  ENOTFOUND: 'Host not found. Check the hostname or IP address.',
  ETIMEDOUT: 'Connection timed out. The server may be unreachable or a firewall is blocking the connection.',
  ER_ACCESS_DENIED_ERROR: 'Access denied. Check your username and password.',
  ER_BAD_DB_ERROR: 'Unknown database. Verify the database name.',
  ER_DBACCESS_DENIED_ERROR: 'Access denied to this database. Check user privileges.',
  ECONNRESET: 'Connection was reset. The server closed the connection unexpectedly.',
  PROTOCOL_CONNECTION_LOST: 'Connection lost. The server may have restarted.',
  ER_NOT_SUPPORTED_AUTH_MODE: 'Authentication method not supported. Try using mysql_native_password.',
  CERT_HAS_EXPIRED: 'SSL certificate has expired.',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'Self-signed SSL certificate. Set rejectUnauthorized to false or provide a valid CA.',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'SSL certificate cannot be verified. Check your CA configuration.'
};

/**
 * Test a MySQL connection with the provided credentials.
 *
 * @param {object} config
 * @param {string} config.host - MySQL server hostname or IP.
 * @param {number} [config.port=3306] - MySQL server port.
 * @param {string} config.user - MySQL username.
 * @param {string} config.password - MySQL password.
 * @param {string} [config.database] - Optional database name.
 * @param {boolean} [config.ssl=false] - Whether to use SSL.
 * @returns {Promise<object>} Connection test result.
 */
async function testConnection(config) {
  const startTime = Date.now();
  let connection = null;

  try {
    const connectionConfig = {
      host: config.host,
      port: config.port || 3306,
      user: config.user,
      password: config.password,
      ...DEFAULT_OPTIONS
    };

    if (config.database) {
      connectionConfig.database = config.database;
    }

    if (config.ssl) {
      connectionConfig.ssl = {
        rejectUnauthorized: config.sslRejectUnauthorized !== false
      };
    }

    connection = await mysql.createConnection(connectionConfig);

    // Run a simple query to verify the connection is fully functional
    await connection.execute('SELECT 1 AS connected');
    const elapsed = Date.now() - startTime;

    // Gather server info
    const [versionRows] = await connection.execute('SELECT VERSION() AS version');
    const serverVersion = versionRows[0] ? versionRows[0].version : 'unknown';

    let databases = [];
    try {
      const [dbRows] = await connection.execute('SHOW DATABASES');
      databases = dbRows.map(row => Object.values(row)[0]);
    } catch (dbListError) {
      // User may not have SHOW DATABASES privilege
      databases = ['(insufficient privileges to list databases)'];
    }

    return {
      success: true,
      message: 'MySQL connection successful.',
      latencyMs: elapsed,
      server: {
        version: serverVersion,
        host: config.host,
        port: config.port || 3306,
        database: config.database || '(none)',
        databases
      }
    };
  } catch (err) {
    const elapsed = Date.now() - startTime;
    const description = ERROR_DESCRIPTIONS[err.code] || ERROR_DESCRIPTIONS[err.errno] || null;

    return {
      success: false,
      message: description || `MySQL connection failed: ${err.message}`,
      error: {
        code: err.code || 'UNKNOWN',
        errno: err.errno || null,
        sqlState: err.sqlState || null,
        sqlMessage: err.sqlMessage || err.message,
        description,
        fatal: err.fatal || false
      },
      latencyMs: elapsed,
      troubleshooting: buildTroubleshooting(err)
    };
  } finally {
    if (connection) {
      try {
        await connection.end();
      } catch (closeErr) {
        // Ignore close errors
      }
    }
  }
}

/**
 * Build troubleshooting suggestions based on the error.
 *
 * @param {Error} err - The MySQL connection error.
 * @returns {string[]} List of troubleshooting steps.
 */
function buildTroubleshooting(err) {
  const steps = [];

  switch (err.code) {
    case 'ECONNREFUSED':
      steps.push('Verify the MySQL server is running on the specified host and port.');
      steps.push('Check firewall rules to ensure the port is open.');
      steps.push('If using a cloud provider, verify the security group / network ACL allows inbound traffic on the MySQL port.');
      break;
    case 'ENOTFOUND':
      steps.push('Double-check the hostname or IP address for typos.');
      steps.push('Verify DNS resolution is working correctly.');
      break;
    case 'ETIMEDOUT':
      steps.push('Check if a firewall or WAF is blocking the connection.');
      steps.push('Verify the server is reachable from this network.');
      steps.push('Try increasing the connection timeout.');
      break;
    case 'ER_ACCESS_DENIED_ERROR':
      steps.push('Verify the username and password are correct.');
      steps.push('Check that the user is allowed to connect from this host (MySQL user@host grants).');
      steps.push("Run: SHOW GRANTS FOR 'username'@'host'; to check permissions.");
      break;
    case 'ER_BAD_DB_ERROR':
      steps.push('Verify the database name is spelled correctly.');
      steps.push('Run: SHOW DATABASES; to list available databases.');
      break;
    case 'ER_NOT_SUPPORTED_AUTH_MODE':
      steps.push("Run: ALTER USER 'username'@'host' IDENTIFIED WITH mysql_native_password BY 'password';");
      steps.push('Then run: FLUSH PRIVILEGES;');
      break;
    default:
      steps.push('Check the MySQL server error log for more details.');
      steps.push('Verify network connectivity with: telnet <host> <port>');
      steps.push('Ensure the MySQL server allows remote connections (bind-address in my.cnf).');
      break;
  }

  return steps;
}

module.exports = {
  testConnection,
  DEFAULT_OPTIONS,
  ERROR_DESCRIPTIONS
};
