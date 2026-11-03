const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

/**
 * Retrieves a 32-byte encryption key from MASTER_ENCRYPTION_KEY environment variable.
 * @returns {Buffer}
 */
function getMasterKey() {
  const rawKey = process.env.MASTER_ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  if (/^[0-9a-fA-F]{64}$/.test(rawKey)) {
    return Buffer.from(rawKey, 'hex');
  }
  return crypto.createHash('sha256').update(rawKey).digest();
}

/**
 * Encrypts sensitive JSON or string credentials using AES-256-GCM authenticated encryption.
 * @param {Object|string} payload
 * @returns {string} Encrypted string formatted as iv:authTag:ciphertext (hex)
 */
function encryptCredentials(payload) {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = getMasterKey();
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypts AES-256-GCM encrypted credentials back to an object or string.
 * @param {string} encryptedPayload
 * @returns {Object|string}
 */
function decryptCredentials(encryptedPayload) {
  if (!encryptedPayload || typeof encryptedPayload !== 'string') {
    throw new Error('Invalid encrypted payload');
  }
  const parts = encryptedPayload.split(':');
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted credential format');
  }

  const [ivHex, authTagHex, encryptedHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const key = getMasterKey();

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  try {
    return JSON.parse(decrypted);
  } catch {
    return decrypted;
  }
}

/**
 * Masks sensitive keys in an object for safe UI display or logging.
 * @param {Object} creds
 * @returns {Object}
 */
function maskCredentials(creds) {
  if (!creds || typeof creds !== 'object') return {};
  const masked = {};
  for (const [k, v] of Object.entries(creds)) {
    if (typeof v === 'string' && v.length > 8) {
      masked[k] = `${v.slice(0, 4)}****${v.slice(-4)}`;
    } else if (typeof v === 'string') {
      masked[k] = '****';
    } else {
      masked[k] = v;
    }
  }
  return masked;
}

module.exports = {
  encryptCredentials,
  decryptCredentials,
  maskCredentials
};
