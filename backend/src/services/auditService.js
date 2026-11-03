const { query, DEFAULT_ORG_ID } = require('../config/db');

/**
 * Records an immutable audit trail entry for security-sensitive actions.
 * @param {Object} params
 * @param {string} [params.organizationId]
 * @param {string|null} [params.userId]
 * @param {string} [params.actorEmail]
 * @param {string} [params.actorRole]
 * @param {string} params.action
 * @param {string} params.resourceType
 * @param {string} [params.resourceId]
 * @param {string} [params.ipAddress]
 * @param {string} [params.userAgent]
 * @param {string} [params.status]
 * @param {Object} [params.details]
 */
async function logAuditEvent({
  organizationId = DEFAULT_ORG_ID,
  userId = null,
  actorEmail = 'system@aegiscloud.io',
  actorRole = 'SYSTEM',
  action,
  resourceType,
  resourceId = null,
  ipAddress = '127.0.0.1',
  userAgent = 'Internal',
  status = 'SUCCESS',
  details = {}
}) {
  try {
    await query(
      `INSERT INTO audit_logs
       (organization_id, user_id, actor_email, actor_role, action, resource_type, resource_id, ip_address, user_agent, status, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        organizationId,
        userId,
        actorEmail,
        actorRole,
        action,
        resourceType,
        resourceId ? String(resourceId) : null,
        ipAddress,
        userAgent,
        status,
        JSON.stringify(details || {})
      ]
    );
  } catch (err) {
    console.error('[AuditService] Failed to write audit log:', err.message);
  }
}

module.exports = {
  logAuditEvent
};
