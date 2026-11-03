const crypto = require('crypto');

let bcryptLib = null;
try {
  bcryptLib = require('bcryptjs');
} catch {
  bcryptLib = null;
}

let jwtLib = null;
try {
  jwtLib = require('jsonwebtoken');
} catch {
  jwtLib = null;
}

/**
 * Hashes a plaintext password using bcryptjs (if installed) or Node's native memory-hard crypto.scrypt.
 * @param {string} password
 * @param {number} [rounds=10]
 * @returns {Promise<string>}
 */
async function hashPassword(password, rounds = 10) {
  if (bcryptLib) {
    return bcryptLib.hash(password, rounds);
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `$scrypt$${salt}$${derived}`;
}

/**
 * Verifies a plaintext password against a stored bcrypt or scrypt hash.
 * @param {string} password
 * @param {string} storedHash
 * @returns {Promise<boolean>}
 */
async function comparePassword(password, storedHash) {
  if (!storedHash) return false;
  if (storedHash.startsWith('$scrypt$')) {
    const parts = storedHash.split('$');
    const salt = parts[2];
    const originalDerived = parts[3];
    const candidateDerived = crypto.scryptSync(String(password), salt, 64).toString('hex');
    return crypto.timingSafeEqual(
      Buffer.from(originalDerived, 'hex'),
      Buffer.from(candidateDerived, 'hex')
    );
  }
  if (bcryptLib) {
    return bcryptLib.compare(password, storedHash);
  }
  return false;
}

/**
 * Parses duration strings like '15m', '2h', '7d' into seconds.
 */
function parseDurationToSeconds(expStr) {
  if (typeof expStr === 'number') return expStr;
  const match = /^(\d+)([smhd])$/.exec(String(expStr || '2h').trim());
  if (!match) return 7200;
  const val = Number(match[1]);
  const unit = match[2];
  if (unit === 's') return val;
  if (unit === 'm') return val * 60;
  if (unit === 'h') return val * 3600;
  if (unit === 'd') return val * 86400;
  return 7200;
}

function base64UrlEncode(strOrBuf) {
  return Buffer.from(strOrBuf)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

/**
 * Signs a standard RFC-7519 HS256 JWT token.
 */
function signJwt(payload, secret, options = {}) {
  if (jwtLib) {
    return jwtLib.sign(payload, secret, options);
  }
  const nowSec = Math.floor(Date.now() / 1000);
  const ttlSec = parseDurationToSeconds(options.expiresIn || '2h');
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = {
    ...payload,
    iat: nowSec,
    exp: nowSec + ttlSec
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedBody = base64UrlEncode(JSON.stringify(body));
  const signingInput = `${encodedHeader}.${encodedBody}`;
  const signature = base64UrlEncode(
    crypto.createHmac('sha256', secret).update(signingInput).digest()
  );

  return `${signingInput}.${signature}`;
}

/**
 * Verifies a standard RFC-7519 HS256 JWT token.
 */
function verifyJwt(token, secret) {
  if (jwtLib) {
    return jwtLib.verify(token, secret);
  }
  if (!token || typeof token !== 'string') {
    throw new Error('Missing token');
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed JWT token');
  }
  const [encodedHeader, encodedBody, signature] = parts;
  const signingInput = `${encodedHeader}.${encodedBody}`;
  const expectedSig = base64UrlEncode(
    crypto.createHmac('sha256', secret).update(signingInput).digest()
  );

  if (signature !== expectedSig) {
    throw new Error('Invalid JWT signature');
  }

  const decoded = JSON.parse(base64UrlDecode(encodedBody));
  const nowSec = Math.floor(Date.now() / 1000);
  if (decoded.exp && nowSec > decoded.exp) {
    throw new Error('JWT token has expired');
  }
  return decoded;
}

module.exports = {
  hashPassword,
  comparePassword,
  signJwt,
  verifyJwt
};
