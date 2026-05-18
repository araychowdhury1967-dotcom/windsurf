/**
 * Settings manager for saving and retrieving key-value settings
 * records in a MySQL database.
 *
 * Automatically creates the `app_settings` table if it does not exist.
 */

const mysql = require('mysql2/promise');
const { DEFAULT_OPTIONS, ERROR_DESCRIPTIONS } = require('./mysql-connector');

const SETTINGS_TABLE = 'app_settings';

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS \`${SETTINGS_TABLE}\` (
    \`id\` INT AUTO_INCREMENT PRIMARY KEY,
    \`setting_key\` VARCHAR(255) NOT NULL UNIQUE,
    \`setting_value\` TEXT,
    \`created_at\` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
`;

/**
 * Build a mysql2 connection config from user-supplied credentials.
 *
 * @param {object} creds
 * @returns {object}
 */
function buildConnectionConfig(creds) {
  const config = {
    host: creds.host,
    port: creds.port || 3306,
    user: creds.user,
    password: creds.password,
    ...DEFAULT_OPTIONS
  };

  if (creds.database) {
    config.database = creds.database;
  }

  if (creds.ssl) {
    config.ssl = {
      rejectUnauthorized: creds.sslRejectUnauthorized !== false
    };
  }

  return config;
}

/**
 * Ensure the settings table exists, creating it if necessary.
 *
 * @param {import('mysql2/promise').Connection} connection
 */
async function ensureTable(connection) {
  await connection.execute(CREATE_TABLE_SQL);
}

/**
 * Save one or more settings records.
 *
 * Each record is an object with `key` and `value` properties.
 * Existing keys are updated (upsert).
 *
 * @param {object} creds - MySQL connection credentials.
 * @param {Array<{key: string, value: string}>} records - Settings to save.
 * @returns {Promise<object>} Result summary.
 */
async function saveSettings(creds, records) {
  if (!creds.database) {
    return {
      success: false,
      message: 'A database name is required to save settings.',
      error: { code: 'VALIDATION_ERROR' }
    };
  }

  if (!Array.isArray(records) || records.length === 0) {
    return {
      success: false,
      message: 'At least one settings record ({key, value}) is required.',
      error: { code: 'VALIDATION_ERROR' }
    };
  }

  const invalid = records.filter(r => !r.key || typeof r.key !== 'string');
  if (invalid.length > 0) {
    return {
      success: false,
      message: 'Every record must have a non-empty string "key".',
      error: { code: 'VALIDATION_ERROR' }
    };
  }

  const startTime = Date.now();
  let connection = null;

  try {
    connection = await mysql.createConnection(buildConnectionConfig(creds));
    await ensureTable(connection);

    const upsertSQL = `
      INSERT INTO \`${SETTINGS_TABLE}\` (\`setting_key\`, \`setting_value\`)
      VALUES (?, ?)
      ON DUPLICATE KEY UPDATE \`setting_value\` = VALUES(\`setting_value\`)
    `;

    const saved = [];
    for (const record of records) {
      const value = record.value != null ? String(record.value) : null;
      await connection.execute(upsertSQL, [record.key, value]);
      saved.push({ key: record.key, value });
    }

    const elapsed = Date.now() - startTime;

    return {
      success: true,
      message: `Saved ${saved.length} setting(s) successfully.`,
      saved,
      latencyMs: elapsed
    };
  } catch (err) {
    const elapsed = Date.now() - startTime;
    const description = ERROR_DESCRIPTIONS[err.code] || ERROR_DESCRIPTIONS[err.errno] || null;
    const fallbackMessage = err.sqlMessage || err.message || err.code || 'Unknown error';

    return {
      success: false,
      message: description || `Failed to save settings records to MySQL: ${fallbackMessage}`,
      error: {
        code: err.code || 'UNKNOWN',
        errno: err.errno || null,
        sqlState: err.sqlState || null,
        sqlMessage: fallbackMessage,
        description,
        fatal: err.fatal || false
      },
      latencyMs: elapsed,
      troubleshooting: buildSaveTroubleshooting(err)
    };
  } finally {
    if (connection) {
      try { await connection.end(); } catch (_e) { /* ignore */ }
    }
  }
}

/**
 * Retrieve settings records from MySQL.
 *
 * @param {object} creds - MySQL connection credentials.
 * @param {string[]} [keys] - Optional list of keys to fetch. Omit to fetch all.
 * @returns {Promise<object>} Result with settings array.
 */
async function getSettings(creds, keys) {
  if (!creds.database) {
    return {
      success: false,
      message: 'A database name is required to retrieve settings.',
      error: { code: 'VALIDATION_ERROR' }
    };
  }

  const startTime = Date.now();
  let connection = null;

  try {
    connection = await mysql.createConnection(buildConnectionConfig(creds));
    await ensureTable(connection);

    let rows;
    if (Array.isArray(keys) && keys.length > 0) {
      const placeholders = keys.map(() => '?').join(', ');
      const sql = `SELECT \`setting_key\`, \`setting_value\`, \`updated_at\` FROM \`${SETTINGS_TABLE}\` WHERE \`setting_key\` IN (${placeholders}) ORDER BY \`setting_key\``;
      [rows] = await connection.execute(sql, keys);
    } else {
      [rows] = await connection.execute(
        `SELECT \`setting_key\`, \`setting_value\`, \`updated_at\` FROM \`${SETTINGS_TABLE}\` ORDER BY \`setting_key\``
      );
    }

    const elapsed = Date.now() - startTime;
    const settings = rows.map(r => ({
      key: r.setting_key,
      value: r.setting_value,
      updatedAt: r.updated_at
    }));

    return {
      success: true,
      message: `Retrieved ${settings.length} setting(s).`,
      settings,
      latencyMs: elapsed
    };
  } catch (err) {
    const elapsed = Date.now() - startTime;
    const description = ERROR_DESCRIPTIONS[err.code] || ERROR_DESCRIPTIONS[err.errno] || null;
    const fallbackMessage = err.sqlMessage || err.message || err.code || 'Unknown error';

    return {
      success: false,
      message: description || `Failed to retrieve settings from MySQL: ${fallbackMessage}`,
      error: {
        code: err.code || 'UNKNOWN',
        errno: err.errno || null,
        sqlState: err.sqlState || null,
        sqlMessage: fallbackMessage,
        description,
        fatal: err.fatal || false
      },
      latencyMs: elapsed,
      troubleshooting: buildSaveTroubleshooting(err)
    };
  } finally {
    if (connection) {
      try { await connection.end(); } catch (_e) { /* ignore */ }
    }
  }
}

/**
 * Delete one or more settings by key.
 *
 * @param {object} creds - MySQL connection credentials.
 * @param {string[]} keys - Keys to delete.
 * @returns {Promise<object>}
 */
async function deleteSettings(creds, keys) {
  if (!creds.database) {
    return {
      success: false,
      message: 'A database name is required to delete settings.',
      error: { code: 'VALIDATION_ERROR' }
    };
  }

  if (!Array.isArray(keys) || keys.length === 0) {
    return {
      success: false,
      message: 'At least one key is required to delete.',
      error: { code: 'VALIDATION_ERROR' }
    };
  }

  const startTime = Date.now();
  let connection = null;

  try {
    connection = await mysql.createConnection(buildConnectionConfig(creds));
    const placeholders = keys.map(() => '?').join(', ');
    const [result] = await connection.execute(
      `DELETE FROM \`${SETTINGS_TABLE}\` WHERE \`setting_key\` IN (${placeholders})`,
      keys
    );

    const elapsed = Date.now() - startTime;
    return {
      success: true,
      message: `Deleted ${result.affectedRows} setting(s).`,
      deletedCount: result.affectedRows,
      latencyMs: elapsed
    };
  } catch (err) {
    const elapsed = Date.now() - startTime;
    const description = ERROR_DESCRIPTIONS[err.code] || ERROR_DESCRIPTIONS[err.errno] || null;
    const fallbackMessage = err.sqlMessage || err.message || err.code || 'Unknown error';

    return {
      success: false,
      message: description || `Failed to delete settings from MySQL: ${fallbackMessage}`,
      error: {
        code: err.code || 'UNKNOWN',
        errno: err.errno || null,
        sqlState: err.sqlState || null,
        sqlMessage: fallbackMessage,
        description,
        fatal: err.fatal || false
      },
      latencyMs: elapsed,
      troubleshooting: buildSaveTroubleshooting(err)
    };
  } finally {
    if (connection) {
      try { await connection.end(); } catch (_e) { /* ignore */ }
    }
  }
}

/**
 * Build troubleshooting steps for settings save/retrieve errors.
 *
 * @param {Error} err
 * @returns {string[]}
 */
function buildSaveTroubleshooting(err) {
  const steps = [];

  switch (err.code) {
    case 'ECONNREFUSED':
      steps.push('Verify the MySQL server is running on the specified host and port.');
      steps.push('Check firewall rules to ensure the port is open.');
      break;
    case 'ER_ACCESS_DENIED_ERROR':
      steps.push('Verify the username and password are correct.');
      steps.push('Check that the user has INSERT/UPDATE/SELECT privileges on the database.');
      break;
    case 'ER_BAD_DB_ERROR':
      steps.push('Verify the database name is spelled correctly.');
      steps.push('Create the database first: CREATE DATABASE your_database;');
      break;
    case 'ER_DBACCESS_DENIED_ERROR':
      steps.push('The user does not have permission to access this database.');
      steps.push('Grant privileges: GRANT ALL ON database.* TO \'user\'@\'host\';');
      break;
    case 'ER_NO_SUCH_TABLE':
      steps.push('The settings table could not be created. Check user privileges.');
      steps.push('The user needs CREATE TABLE permission on the database.');
      break;
    case 'ETIMEDOUT':
      steps.push('The connection timed out. The server may be unreachable.');
      steps.push('Check if a firewall or WAF is blocking the connection.');
      break;
    default:
      steps.push('Check the MySQL server error log for more details.');
      steps.push('Verify the user has sufficient privileges (SELECT, INSERT, UPDATE, DELETE, CREATE).');
      steps.push('Ensure network connectivity to the MySQL server.');
      break;
  }

  return steps;
}

module.exports = {
  SETTINGS_TABLE,
  saveSettings,
  getSettings,
  deleteSettings,
  buildConnectionConfig,
  ensureTable
};
