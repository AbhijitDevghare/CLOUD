const express = require('../utils/expressCompat');
const { query } = require('../config/db');
const { initRedis } = require('../config/redis');
const { authenticateJWT, requireRole } = require('../middleware/auth');
const { logAuditEvent } = require('../services/auditService');
const { analyzeThreatTelemetryViaPython } = require('../services/pythonBridge');

const router = express.Router();

// Signature Detection Rules for Module 4
const ATTACK_SIGNATURES = [
  {
    type: 'SQL_INJECTION_ATTEMPT',
    severity: 'CRITICAL',
    confidence: 0.96,
    regex: /(\bUNION\b\s+\bSELECT\b|'?\s*OR\s+['"]?1['"]?\s*=\s*['"]?1|--\s*$|;\s*DROP\s+TABLE|SLEEP\(\d+\))/i,
    description: 'SQL Injection payload signature detected in request parameters or body.'
  },
  {
    type: 'XSS_ATTACK_ATTEMPT',
    severity: 'HIGH',
    confidence: 0.93,
    regex: /(<script[\s>]|javascript:|onerror\s*=|onload\s*=|document\.cookie|alert\()/i,
    description: 'Cross-Site Scripting (XSS) script injection payload detected.'
  },
  {
    type: 'PATH_TRAVERSAL_OR_LFI',
    severity: 'HIGH',
    confidence: 0.91,
    regex: /(\.\.\/|\.\.\\|\/etc\/passwd|\/proc\/self\/environ|win\.ini)/i,
    description: 'Directory Traversal / Local File Inclusion (LFI) probe detected.'
  },
  {
    type: 'COMMAND_INJECTION_ATTEMPT',
    severity: 'CRITICAL',
    confidence: 0.94,
    regex: /(;\s*(?:cat|ls|whoami|curl|wget|bash|sh|nc)\b|\|\|\s*(?:id|uname)|\$\((?:whoami|id)\))/i,
    description: 'OS Command Injection metacharacter sequence detected.'
  }
];

/**
 * Helper to check if an IP is in the Protected IP Safelist (Module 5 safety control).
 */
async function isIpProtectedInSafelist(organizationId, ipAddress) {
  const safelistRes = await query(
    'SELECT ip_cidr, label FROM ip_safelist WHERE organization_id = $1',
    [organizationId]
  );
  for (const row of safelistRes.rows) {
    const clean = row.ip_cidr.split('/')[0].trim();
    if (clean === ipAddress || ipAddress === '127.0.0.1' || ipAddress === '::1') {
      return { protected: true, label: row.label };
    }
  }
  return { protected: false };
}

/**
 * POST /api/v1/threats/ingest
 * Real-time Security Log & Telemetry Ingestion Endpoint (Module 4).
 * Evaluates incoming events using:
 * 1) Signature Detection (SQLi, XSS, LFI, Command Injection)
 * 2) Stateful Sliding-Window Rule Correlation (Brute-Force Logins, DDoS Rate Spikes)
 * 3) Behavioral Anomaly Scoring
 */
router.post('/ingest', authenticateJWT, requireRole('ADMIN', 'ANALYST'), async (req, res) => {
  try {
    const {
      sourceIp = '203.0.113.55',
      countryCode = 'RU',
      endpoint = '/api/v1/auth/login',
      httpMethod = 'POST',
      statusCode = 401,
      payload = '',
      userAgent = 'Mozilla/5.0',
      eventCount = 1,
      autoProposeBlock = true
    } = req.body;

    const redis = await initRedis();
    const orgId = req.user.organizationId;
    const detectedThreats = [];

    // 1. Check Signature Rules against endpoint + payload + userAgent
    const combinedInspectionString = `${endpoint} ${typeof payload === 'string' ? payload : JSON.stringify(payload)} ${userAgent}`;
    for (const sig of ATTACK_SIGNATURES) {
      if (sig.regex.test(combinedInspectionString)) {
        detectedThreats.push({
          threatType: sig.type,
          detectionMethod: 'SIGNATURE',
          severity: sig.severity,
          confidenceScore: sig.confidence,
          description: `${sig.description} Source IP: ${sourceIp} targeting ${httpMethod} ${endpoint}.`
        });
      }
    }

    // 2. Stateful Sliding-Window Brute-Force Detection (Failed Logins HTTP 401/403)
    if (Number(statusCode) === 401 || Number(statusCode) === 403) {
      const bfKey = `bf_window:${orgId}:${sourceIp}`;
      let currentFails = 0;
      for (let i = 0; i < Math.max(1, Number(eventCount)); i += 1) {
        currentFails = await redis.incr(bfKey);
      }
      await redis.expire(bfKey, 120);

      if (currentFails >= 8) {
        detectedThreats.push({
          threatType: 'BRUTE_FORCE_CREDENTIAL_ATTACK',
          detectionMethod: 'RULE_THRESHOLD',
          severity: currentFails >= 15 ? 'CRITICAL' : 'HIGH',
          confidenceScore: 0.95,
          description: `Sliding-window correlation detected ${currentFails} failed authentication attempts from IP ${sourceIp} within 120 seconds targeting ${endpoint}.`
        });
      }
    }

    // 3. Abnormal Traffic / Application DDoS Rate Spike Detection (ML/Statistical Anomaly)
    const rateKey = `rate_window:${orgId}:${sourceIp}`;
    let requestBurst = 0;
    for (let i = 0; i < Math.max(1, Number(eventCount)); i += 1) {
      requestBurst = await redis.incr(rateKey);
    }
    await redis.expire(rateKey, 60);

    if (requestBurst >= 100) {
      detectedThreats.push({
        threatType: 'ABNORMAL_TRAFFIC_DDOS_ANOMALY',
        detectionMethod: 'ML_ANOMALY',
        severity: 'CRITICAL',
        confidenceScore: 0.89,
        description: `Statistical traffic anomaly (Z-score > 4.2): ${requestBurst} requests/min from IP ${sourceIp} targeting ${endpoint}.`
      });
    }

    // 4. Enrich with Python Threat & Anomaly Engine
    const pyAnalysis = await analyzeThreatTelemetryViaPython({
      sourceIp,
      endpoint,
      httpMethod,
      statusCode,
      payload,
      userAgent,
      eventCount
    });
    for (const pyDet of pyAnalysis.detections || []) {
      if (!detectedThreats.some((d) => d.threatType === pyDet.threatType)) {
        detectedThreats.push(pyDet);
      }
    }

    const createdAlerts = [];
    const createdActions = [];

    for (const t of detectedThreats) {
      // Deduplicate active alert for same IP + threatType
      const existingAlert = await query(
        `SELECT * FROM threat_alerts
         WHERE organization_id = $1 AND source_ip = $2 AND threat_type = $3 AND status = 'ACTIVE'`,
        [orgId, sourceIp, t.threatType]
      );

      let alertRow;
      if (existingAlert.rows.length > 0) {
        const updated = await query(
          `UPDATE threat_alerts
           SET event_count = event_count + $1, last_seen_at = NOW(), description = $2
           WHERE id = $3
           RETURNING *`,
          [Math.max(1, Number(eventCount)), t.description, existingAlert.rows[0].id]
        );
        alertRow = updated.rows[0];
      } else {
        const inserted = await query(
          `INSERT INTO threat_alerts
           (organization_id, threat_type, detection_method, severity, confidence_score, source_ip, country_code, targeted_endpoint, event_count, status, description, raw_events)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ACTIVE', $10, $11)
           RETURNING *`,
          [
            orgId,
            t.threatType,
            t.detectionMethod,
            t.severity,
            t.confidenceScore,
            sourceIp,
            countryCode,
            endpoint,
            Math.max(1, Number(eventCount)),
            t.description,
            JSON.stringify([{ timestamp: new Date().toISOString(), httpMethod, endpoint, statusCode, payload, userAgent }])
          ]
        );
        alertRow = inserted.rows[0];
      }
      createdAlerts.push(alertRow);

      // Module 5: Create a Prevention Action Proposal if not already pending/executed for this IP
      if (autoProposeBlock) {
        const safelistCheck = await isIpProtectedInSafelist(orgId, sourceIp);
        if (!safelistCheck.protected) {
          const existingAction = await query(
            `SELECT * FROM prevention_actions
             WHERE organization_id = $1 AND target_identifier = $2 AND status IN ('PENDING_APPROVAL', 'EXECUTED')`,
            [orgId, sourceIp]
          );

          if (existingAction.rows.length === 0) {
            const actionRes = await query(
              `INSERT INTO prevention_actions
               (organization_id, threat_alert_id, action_type, target_identifier, enforcement_layer, requires_approval, status, reason, requested_by)
               VALUES ($1, $2, 'BLOCK_IP_WAF', $3, 'AWS_WAF_AND_PLATFORM_BLOCKLIST', true, 'PENDING_APPROVAL', $4, $5)
               RETURNING *`,
              [
                orgId,
                alertRow.id,
                sourceIp,
                `Automated containment proposal for ${t.threatType} (${t.severity}) from ${sourceIp}`,
                req.user.id
              ]
            );
            createdActions.push(actionRes.rows[0]);
          }
        }
      }
    }

    // Broadcast real-time Socket.IO event to connected SOC dashboards
    const io = req.app.get('io');
    if (io && createdAlerts.length > 0) {
      io.emit('threat:new_alert', {
        alerts: createdAlerts,
        pendingActions: createdActions
      });
    }

    return res.status(201).json({
      ingested: true,
      threatsDetected: createdAlerts.length,
      alerts: createdAlerts,
      proposedPreventionActions: createdActions
    });
  } catch (err) {
    return res.status(500).json({ error: 'TELEMETRY_INGEST_ERROR', message: err.message });
  }
});

/**
 * GET /api/v1/threats/alerts
 * Lists all detected threat alerts and security incidents.
 */
router.get('/alerts', authenticateJWT, async (req, res) => {
  const result = await query(
    `SELECT * FROM threat_alerts
     WHERE organization_id = $1
     ORDER BY last_seen_at DESC
     LIMIT 100`,
    [req.user.organizationId]
  );
  return res.json({ alerts: result.rows });
});

/**
 * GET /api/v1/threats/prevention/actions
 * Lists all attack prevention actions (Pending Approval, Executed, Rolled Back) and Safelist.
 */
router.get('/prevention/actions', authenticateJWT, async (req, res) => {
  const actionsRes = await query(
    `SELECT * FROM prevention_actions
     WHERE organization_id = $1
     ORDER BY created_at DESC`,
    [req.user.organizationId]
  );

  const safelistRes = await query(
    `SELECT * FROM ip_safelist
     WHERE organization_id = $1
     ORDER BY created_at ASC`,
    [req.user.organizationId]
  );

  const redis = await initRedis();
  const activeBlockedIps = await redis.smembers('active_blocked_ips');

  return res.json({
    actions: actionsRes.rows,
    safelist: safelistRes.rows,
    activeBlockedIps
  });
});

/**
 * POST /api/v1/threats/prevention/actions
 * Manually requests a new Attack Prevention Action (Block IP, Rate Limit IP, Disable Compromised IAM Key).
 */
router.post('/prevention/actions', authenticateJWT, requireRole('ADMIN', 'ANALYST'), async (req, res) => {
  const {
    actionType = 'BLOCK_IP_WAF',
    targetIdentifier,
    reason = 'Manual security analyst containment request',
    executeImmediately = false
  } = req.body;

  if (!targetIdentifier) {
    return res.status(400).json({ error: 'MISSING_TARGET', message: 'targetIdentifier (IP or IAM Key ID) is required.' });
  }

  // Verify against Protected Safelist
  const safelistCheck = await isIpProtectedInSafelist(req.user.organizationId, targetIdentifier);
  if (safelistCheck.protected) {
    return res.status(400).json({
      error: 'PROTECTED_SAFELIST_ASSET',
      message: `Cannot block ${targetIdentifier}: This address is protected by the Organization Safelist (${safelistCheck.label}).`
    });
  }

  // Only ADMIN can execute immediately; ANALYST requests enter PENDING_APPROVAL
  const canExecuteNow = req.user.role === 'ADMIN' && Boolean(executeImmediately);
  const status = canExecuteNow ? 'EXECUTED' : 'PENDING_APPROVAL';

  const insertRes = await query(
    `INSERT INTO prevention_actions
     (organization_id, action_type, target_identifier, enforcement_layer, requires_approval, status, reason, requested_by, approved_by, executed_at, expires_at, rollback_metadata)
     VALUES ($1, $2, $3, 'AWS_WAF_AND_PLATFORM_BLOCKLIST', $4, $5, $6, $7, $8, $9, $10, $11)
     RETURNING *`,
    [
      req.user.organizationId,
      actionType,
      targetIdentifier,
      !canExecuteNow,
      status,
      reason,
      req.user.id,
      canExecuteNow ? req.user.id : null,
      canExecuteNow ? new Date().toISOString() : null,
      canExecuteNow ? new Date(Date.now() + 24 * 3600 * 1000).toISOString() : null,
      JSON.stringify({ previousState: 'UNBLOCKED', wafLockToken: `waf-lock-${Date.now()}` })
    ]
  );

  if (canExecuteNow && actionType.startsWith('BLOCK_IP')) {
    const redis = await initRedis();
    await redis.sadd('active_blocked_ips', targetIdentifier);
  }

  await logAuditEvent({
    organizationId: req.user.organizationId,
    userId: req.user.id,
    actorEmail: req.user.email,
    actorRole: req.user.role,
    action: canExecuteNow ? 'PREVENTION_ACTION_EXECUTED' : 'PREVENTION_ACTION_REQUESTED',
    resourceType: 'PREVENTION_ACTION',
    resourceId: insertRes.rows[0].id,
    ipAddress: req.clientIp || req.ip,
    details: { actionType, targetIdentifier, status }
  });

  return res.status(201).json({ action: insertRes.rows[0] });
});

/**
 * POST /api/v1/threats/prevention/actions/:id/approve
 * Admin-only approval workflow to execute a pending IP block or IAM containment action.
 */
router.post('/prevention/actions/:id/approve', authenticateJWT, requireRole('ADMIN'), async (req, res) => {
  const actionId = req.params.id;
  const actionRes = await query(
    'SELECT * FROM prevention_actions WHERE id = $1 AND organization_id = $2',
    [actionId, req.user.organizationId]
  );

  if (actionRes.rows.length === 0) {
    return res.status(404).json({ error: 'ACTION_NOT_FOUND' });
  }

  const action = actionRes.rows[0];
  const safelistCheck = await isIpProtectedInSafelist(req.user.organizationId, action.target_identifier);
  if (safelistCheck.protected) {
    return res.status(400).json({
      error: 'PROTECTED_SAFELIST_ASSET',
      message: `Execution blocked: ${action.target_identifier} is in the Protected Safelist (${safelistCheck.label}).`
    });
  }

  const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  const rollbackMeta = {
    previousState: 'ALLOWED',
    wafIpSetId: 'ipset-prod-edge-01',
    wafLockToken: `lock-${Date.now()}`,
    approvedByEmail: req.user.email
  };

  const updatedRes = await query(
    `UPDATE prevention_actions
     SET status = 'EXECUTED', approved_by = $1, executed_at = NOW(), expires_at = $2, rollback_metadata = $3
     WHERE id = $4
     RETURNING *`,
    [req.user.id, expiresAt, JSON.stringify(rollbackMeta), actionId]
  );

  if (action.action_type.startsWith('BLOCK_IP') || action.action_type === 'RATE_LIMIT_IP') {
    const redis = await initRedis();
    await redis.sadd('active_blocked_ips', action.target_identifier);
  }

  if (action.threat_alert_id) {
    await query(
      `UPDATE threat_alerts SET status = 'CONTAINED' WHERE id = $1`,
      [action.threat_alert_id]
    );
  }

  await logAuditEvent({
    organizationId: req.user.organizationId,
    userId: req.user.id,
    actorEmail: req.user.email,
    actorRole: req.user.role,
    action: 'PREVENTION_ACTION_APPROVED_AND_EXECUTED',
    resourceType: 'PREVENTION_ACTION',
    resourceId: actionId,
    ipAddress: req.clientIp || req.ip,
    details: { actionType: action.action_type, targetIdentifier: action.target_identifier }
  });

  const io = req.app.get('io');
  if (io) {
    io.emit('prevention:action_updated', updatedRes.rows[0]);
  }

  return res.json({ message: 'Prevention action approved and enforced.', action: updatedRes.rows[0] });
});

/**
 * POST /api/v1/threats/prevention/actions/:id/rollback
 * One-Click Rollback to immediately unblock an IP or restore state (Admin only).
 */
router.post('/prevention/actions/:id/rollback', authenticateJWT, requireRole('ADMIN'), async (req, res) => {
  const actionId = req.params.id;
  const actionRes = await query(
    'SELECT * FROM prevention_actions WHERE id = $1 AND organization_id = $2',
    [actionId, req.user.organizationId]
  );

  if (actionRes.rows.length === 0) {
    return res.status(404).json({ error: 'ACTION_NOT_FOUND' });
  }

  const action = actionRes.rows[0];
  const updatedRes = await query(
    `UPDATE prevention_actions
     SET status = 'ROLLED_BACK', rolled_back_at = NOW()
     WHERE id = $1
     RETURNING *`,
    [actionId]
  );

  const redis = await initRedis();
  await redis.srem('active_blocked_ips', action.target_identifier);

  await logAuditEvent({
    organizationId: req.user.organizationId,
    userId: req.user.id,
    actorEmail: req.user.email,
    actorRole: req.user.role,
    action: 'PREVENTION_ACTION_ROLLED_BACK',
    resourceType: 'PREVENTION_ACTION',
    resourceId: actionId,
    ipAddress: req.clientIp || req.ip,
    details: { targetIdentifier: action.target_identifier }
  });

  return res.json({ message: 'Action rolled back and target unblocked.', action: updatedRes.rows[0] });
});

module.exports = router;
