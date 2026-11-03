const { verifyJwt } = require('../utils/cryptoAuth');
const { initRedis } = require('../config/redis');
const { logAuditEvent } = require('../services/auditService');

const ACCESS_SECRET =
  process.env.JWT_ACCESS_SECRET || 'jwt_access_secret_key_change_in_production_min_32_chars_long_01';

/**
 * Middleware that enforces active IP blocklist checks from Module 5 (Attack Prevention).
 */
async function enforceIpBlocklist(req, res, next) {
  try {
    const clientIp =
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      req.socket?.remoteAddress ||
      '127.0.0.1';

    const redis = await initRedis();
    const isBlocked = await redis.sismember('active_blocked_ips', clientIp);
    if (isBlocked) {
      return res.status(403).json({
        error: 'ACCESS_BLOCKED_BY_SECURITY_POLICY',
        message: `Your IP address (${clientIp}) has been blocked by AegisCloud Active Threat Prevention.`
      });
    }
    req.clientIp = clientIp;
    next();
  } catch {
    next();
  }
}

/**
 * Verifies the Bearer JWT Access Token and checks Redis revocation blocklist.
 */
async function authenticateJWT(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required. Please provide a valid Bearer JWT token.'
      });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyJwt(token, ACCESS_SECRET);

    const redis = await initRedis();
    const isRevoked = await redis.get(`revoked_jwt:${token}`);
    if (isRevoked) {
      return res.status(401).json({
        error: 'SESSION_REVOKED',
        message: 'This session token has been revoked. Please log in again.'
      });
    }

    req.user = {
      id: decoded.sub,
      email: decoded.email,
      fullName: decoded.fullName,
      role: decoded.role,
      organizationId: decoded.organizationId
    };
    req.rawToken = token;
    next();
  } catch {
    return res.status(401).json({
      error: 'INVALID_OR_EXPIRED_TOKEN',
      message: 'Invalid or expired authentication token.'
    });
  }
}

/**
 * Role-Based Access Control (RBAC) middleware factory.
 * @param {...string} allowedRoles - e.g. 'ADMIN', 'ANALYST', 'AUDITOR'
 */
function requireRole(...allowedRoles) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'User context missing.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      await logAuditEvent({
        organizationId: req.user.organizationId,
        userId: req.user.id,
        actorEmail: req.user.email,
        actorRole: req.user.role,
        action: 'RBAC_ACCESS_DENIED',
        resourceType: req.baseUrl || req.originalUrl,
        ipAddress: req.clientIp || req.ip,
        userAgent: req.headers['user-agent'],
        status: 'DENIED',
        details: {
          requiredRoles: allowedRoles,
          attemptedMethod: req.method,
          attemptedPath: req.originalUrl
        }
      });

      return res.status(403).json({
        error: 'FORBIDDEN_INSUFFICIENT_ROLE',
        message: `Access denied. Required role(s): ${allowedRoles.join(', ')}. Your role: ${req.user.role}.`
      });
    }

    next();
  };
}

module.exports = {
  enforceIpBlocklist,
  authenticateJWT,
  requireRole,
  ACCESS_SECRET
};
