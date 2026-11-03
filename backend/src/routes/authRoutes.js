const express = require('../utils/expressCompat');
const crypto = require('crypto');
const Joi = require('../utils/validator');
const { hashPassword, comparePassword, signJwt } = require('../utils/cryptoAuth');
const { query, DEFAULT_ORG_ID } = require('../config/db');
const { initRedis } = require('../config/redis');
const { authenticateJWT, requireRole, ACCESS_SECRET } = require('../middleware/auth');
const { logAuditEvent } = require('../services/auditService');

const router = express.Router();

const REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || 'jwt_refresh_secret_key_change_in_production_min_32_chars_long_02';

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required(),
  fullName: Joi.string().min(2).max(120).required(),
  role: Joi.string().valid('ADMIN', 'ANALYST', 'AUDITOR').default('ANALYST')
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

function signTokens(user) {
  const payload = {
    sub: user.id,
    email: user.email,
    fullName: user.full_name,
    role: user.role,
    organizationId: user.organization_id
  };

  const accessToken = signJwt(payload, ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '2h'
  });

  const refreshToken = signJwt(
    { sub: user.id, jti: crypto.randomUUID() },
    REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );

  return { accessToken, refreshToken };
}

/**
 * POST /api/v1/auth/login
 * Authenticates user, enforces 5-attempt lockout, issues JWT + Refresh Token, and writes Audit Log.
 */
router.post('/login', async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: error.details[0].message });
    }

    const email = value.email.toLowerCase().trim();
    const userRes = await query('SELECT * FROM users WHERE email = $1', [email]);
    const user = userRes.rows[0];
    const clientIp = req.clientIp || req.ip || '127.0.0.1';

    if (!user) {
      await logAuditEvent({
        action: 'USER_LOGIN_FAILED',
        resourceType: 'AUTH',
        actorEmail: email,
        ipAddress: clientIp,
        userAgent: req.headers['user-agent'],
        status: 'FAILURE',
        details: { reason: 'Account not found' }
      });
      return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
    }

    if (!user.is_active) {
      return res.status(403).json({ error: 'ACCOUNT_DISABLED', message: 'This user account has been disabled by an administrator.' });
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({
        error: 'ACCOUNT_LOCKED',
        message: `Account temporarily locked due to repeated failed logins until ${new Date(user.locked_until).toISOString()}.`
      });
    }

    const passwordValid = await comparePassword(value.password, user.password_hash);
    if (!passwordValid) {
      const attempts = (user.failed_login_attempts || 0) + 1;
      const lockUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000).toISOString() : null;

      await query(
        'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
        [attempts, lockUntil, user.id]
      );

      await logAuditEvent({
        organizationId: user.organization_id,
        userId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'USER_LOGIN_FAILED',
        resourceType: 'AUTH',
        ipAddress: clientIp,
        userAgent: req.headers['user-agent'],
        status: 'FAILURE',
        details: { failedAttempts: attempts, accountLocked: Boolean(lockUntil) }
      });

      return res.status(401).json({
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password.',
        remainingAttempts: Math.max(0, 5 - attempts)
      });
    }

    // Reset failed login counter and update last login metadata
    await query(
      `UPDATE users
       SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW(), last_login_ip = $1
       WHERE id = $2`,
      [clientIp, user.id]
    );

    const { accessToken, refreshToken } = signTokens(user);
    const refreshHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    await query(
      `INSERT INTO user_sessions (user_id, refresh_token_hash, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        user.id,
        refreshHash,
        clientIp,
        req.headers['user-agent'] || 'Unknown',
        new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString()
      ]
    );

    await logAuditEvent({
      organizationId: user.organization_id,
      userId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'USER_LOGIN_SUCCESS',
      resourceType: 'AUTH',
      resourceId: user.id,
      ipAddress: clientIp,
      userAgent: req.headers['user-agent'],
      status: 'SUCCESS'
    });

    return res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        organizationId: user.organization_id,
        mfaEnabled: user.mfa_enabled
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'LOGIN_ERROR', message: err.message });
  }
});

/**
 * POST /api/v1/auth/register
 * Registers a new user (Admin only when authenticated, or self-registration for initial analyst onboarding).
 */
router.post('/register', async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: error.details[0].message });
    }

    const email = value.email.toLowerCase().trim();
    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'EMAIL_EXISTS', message: 'A user with this email already exists.' });
    }

    const passwordHash = await hashPassword(value.password, 10);
    const insertRes = await query(
      `INSERT INTO users (organization_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id, organization_id, email, full_name, role, is_active, created_at`,
      [DEFAULT_ORG_ID, email, passwordHash, value.fullName, value.role]
    );

    const newUser = insertRes.rows[0];
    await logAuditEvent({
      organizationId: DEFAULT_ORG_ID,
      userId: newUser.id,
      actorEmail: newUser.email,
      actorRole: newUser.role,
      action: 'USER_REGISTERED',
      resourceType: 'USER',
      resourceId: newUser.id,
      ipAddress: req.clientIp || req.ip,
      details: { assignedRole: newUser.role }
    });

    const { accessToken, refreshToken } = signTokens(newUser);
    return res.status(201).json({
      accessToken,
      refreshToken,
      user: {
        id: newUser.id,
        email: newUser.email,
        fullName: newUser.full_name,
        role: newUser.role,
        organizationId: newUser.organization_id
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'REGISTRATION_ERROR', message: err.message });
  }
});

/**
 * POST /api/v1/auth/logout
 * Revokes the current JWT access token in Redis and marks refresh sessions revoked.
 */
router.post('/logout', authenticateJWT, async (req, res) => {
  try {
    const redis = await initRedis();
    await redis.set(`revoked_jwt:${req.rawToken}`, 'true', 'EX', 7200);
    await query('UPDATE user_sessions SET is_revoked = true WHERE user_id = $1', [req.user.id]);

    await logAuditEvent({
      organizationId: req.user.organizationId,
      userId: req.user.id,
      actorEmail: req.user.email,
      actorRole: req.user.role,
      action: 'USER_LOGOUT',
      resourceType: 'AUTH',
      resourceId: req.user.id,
      ipAddress: req.clientIp || req.ip
    });

    return res.json({ message: 'Logged out and session token revoked.' });
  } catch (err) {
    return res.status(500).json({ error: 'LOGOUT_ERROR', message: err.message });
  }
});

/**
 * GET /api/v1/auth/me
 * Returns current authenticated user profile and RBAC capabilities.
 */
router.get('/me', authenticateJWT, async (req, res) => {
  const userRes = await query(
    'SELECT id, organization_id, email, full_name, role, is_active, mfa_enabled, last_login_at, last_login_ip, created_at FROM users WHERE id = $1',
    [req.user.id]
  );
  if (userRes.rows.length === 0) {
    return res.status(404).json({ error: 'USER_NOT_FOUND' });
  }
  const u = userRes.rows[0];
  return res.json({
    id: u.id,
    organizationId: u.organization_id,
    email: u.email,
    fullName: u.full_name,
    role: u.role,
    isActive: u.is_active,
    mfaEnabled: u.mfa_enabled,
    lastLoginAt: u.last_login_at,
    lastLoginIp: u.last_login_ip
  });
});

/**
 * GET /api/v1/auth/users
 * Lists all platform users in the organization (Admin & Auditor access).
 */
router.get('/users', authenticateJWT, requireRole('ADMIN', 'AUDITOR'), async (req, res) => {
  const result = await query(
    `SELECT id, email, full_name, role, is_active, mfa_enabled, failed_login_attempts, last_login_at, last_login_ip, created_at
     FROM users
     WHERE organization_id = $1
     ORDER BY created_at ASC`,
    [req.user.organizationId]
  );
  return res.json({ users: result.rows });
});

/**
 * PATCH /api/v1/auth/users/:id
 * Admin-only endpoint to update a user's RBAC role or active status.
 */
router.patch('/users/:id', authenticateJWT, requireRole('ADMIN'), async (req, res) => {
  const { role, isActive } = req.body;
  const targetUserId = req.params.id;

  const currentRes = await query('SELECT * FROM users WHERE id = $1 AND organization_id = $2', [
    targetUserId,
    req.user.organizationId
  ]);
  if (currentRes.rows.length === 0) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'Target user not found.' });
  }

  const current = currentRes.rows[0];
  const updatedRole = role && ['ADMIN', 'ANALYST', 'AUDITOR'].includes(role) ? role : current.role;
  const updatedActive = typeof isActive === 'boolean' ? isActive : current.is_active;

  await query(
    'UPDATE users SET role = $1, is_active = $2, updated_at = NOW() WHERE id = $3',
    [updatedRole, updatedActive, targetUserId]
  );

  await logAuditEvent({
    organizationId: req.user.organizationId,
    userId: req.user.id,
    actorEmail: req.user.email,
    actorRole: req.user.role,
    action: 'USER_RBAC_UPDATED',
    resourceType: 'USER',
    resourceId: targetUserId,
    ipAddress: req.clientIp || req.ip,
    details: { targetEmail: current.email, previousRole: current.role, newRole: updatedRole, isActive: updatedActive }
  });

  return res.json({ message: 'User updated successfully', id: targetUserId, role: updatedRole, isActive: updatedActive });
});

/**
 * GET /api/v1/auth/audit-logs
 * Returns immutable platform audit logs (Admin and Auditor access, or own logs for Analyst).
 */
router.get('/audit-logs', authenticateJWT, async (req, res) => {
  const limit = Math.min(200, Number(req.query.limit) || 100);
  if (['ADMIN', 'AUDITOR'].includes(req.user.role)) {
    const logs = await query(
      `SELECT * FROM audit_logs
       WHERE organization_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [req.user.organizationId, limit]
    );
    return res.json({ auditLogs: logs.rows });
  }

  const ownLogs = await query(
    `SELECT * FROM audit_logs
     WHERE organization_id = $1 AND user_id = $2
     ORDER BY created_at DESC
     LIMIT $3`,
    [req.user.organizationId, req.user.id, limit]
  );
  return res.json({ auditLogs: ownLogs.rows });
});

module.exports = router;
