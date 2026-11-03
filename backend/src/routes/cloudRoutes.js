const express = require('../utils/expressCompat');
const Joi = require('../utils/validator');
const { query } = require('../config/db');
const { authenticateJWT, requireRole } = require('../middleware/auth');
const { encryptCredentials, decryptCredentials, maskCredentials } = require('../utils/encryption');
const { executeCloudPostureScan } = require('../services/pythonBridge');
const { recalculateComplianceStatus } = require('../services/complianceEngine');
const { logAuditEvent } = require('../services/auditService');

const router = express.Router();

const connectCloudSchema = Joi.object({
  provider: Joi.string().valid('AWS', 'AZURE', 'GCP').required(),
  accountName: Joi.string().min(3).max(150).required(),
  accountIdentifier: Joi.string().min(3).max(150).required(),
  authMethod: Joi.string().valid('IAM_ASSUME_ROLE', 'ACCESS_KEY', 'SERVICE_PRINCIPAL', 'SERVICE_ACCOUNT').required(),
  credentials: Joi.object().required(),
  regions: Joi.array().items(Joi.string()).default(['us-east-1']),
  connectionMode: Joi.string().valid('LIVE', 'DEMO_SIMULATION').default('DEMO_SIMULATION')
});

/**
 * GET /api/v1/cloud/accounts
 * Lists all connected cloud accounts, resource counts, and posture scores.
 */
router.get('/accounts', authenticateJWT, async (req, res) => {
  const accountsRes = await query(
    `SELECT id, provider, account_name, account_identifier, auth_method, regions,
            connection_mode, status, last_scanned_at, security_score, created_at
     FROM cloud_accounts
     WHERE organization_id = $1
     ORDER BY created_at DESC`,
    [req.user.organizationId]
  );

  const resourcesRes = await query(
    `SELECT cloud_account_id, COUNT(*)::int AS resource_count
     FROM cloud_resources
     WHERE organization_id = $1
     GROUP BY cloud_account_id`,
    [req.user.organizationId]
  );

  const resourceMap = {};
  for (const row of resourcesRes.rows) {
    resourceMap[row.cloud_account_id] = row.resource_count;
  }

  const accounts = accountsRes.rows.map((acc) => ({
    ...acc,
    resource_count: resourceMap[acc.id] || 0
  }));

  return res.json({ accounts });
});

/**
 * POST /api/v1/cloud/accounts
 * Connects a new AWS, Azure, or GCP account with AES-256-GCM credential encryption (Admin only).
 */
router.post('/accounts', authenticateJWT, requireRole('ADMIN'), async (req, res) => {
  try {
    const { error, value } = connectCloudSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: error.details[0].message });
    }

    const encrypted = encryptCredentials(value.credentials);
    const insertRes = await query(
      `INSERT INTO cloud_accounts
       (organization_id, provider, account_name, account_identifier, auth_method, encrypted_credentials, regions, connection_mode, status, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'CONNECTED', $9)
       RETURNING id, provider, account_name, account_identifier, auth_method, regions, connection_mode, status, security_score, created_at`,
      [
        req.user.organizationId,
        value.provider,
        value.accountName,
        value.accountIdentifier,
        value.authMethod,
        encrypted,
        JSON.stringify(value.regions),
        value.connectionMode,
        req.user.id
      ]
    );

    const newAccount = insertRes.rows[0];
    await logAuditEvent({
      organizationId: req.user.organizationId,
      userId: req.user.id,
      actorEmail: req.user.email,
      actorRole: req.user.role,
      action: 'CLOUD_ACCOUNT_CONNECTED',
      resourceType: 'CLOUD_ACCOUNT',
      resourceId: newAccount.id,
      ipAddress: req.clientIp || req.ip,
      details: {
        provider: value.provider,
        accountIdentifier: value.accountIdentifier,
        connectionMode: value.connectionMode,
        maskedCredentials: maskCredentials(value.credentials)
      }
    });

    return res.status(201).json({ account: newAccount });
  } catch (err) {
    return res.status(500).json({ error: 'CLOUD_CONNECT_ERROR', message: err.message });
  }
});

/**
 * POST /api/v1/cloud/accounts/:id/scan
 * Executes a Cloud Security Posture Management (CSPM) discovery and misconfiguration scan.
 */
router.post('/accounts/:id/scan', authenticateJWT, requireRole('ADMIN', 'ANALYST'), async (req, res) => {
  try {
    const accountId = req.params.id;
    const accRes = await query(
      'SELECT * FROM cloud_accounts WHERE id = $1 AND organization_id = $2',
      [accountId, req.user.organizationId]
    );

    if (accRes.rows.length === 0) {
      return res.status(404).json({ error: 'ACCOUNT_NOT_FOUND', message: 'Cloud account not found.' });
    }

    const account = accRes.rows[0];
    const decryptedCreds = decryptCredentials(account.encrypted_credentials);
    const regions = Array.isArray(account.regions) ? account.regions : JSON.parse(account.regions || '["us-east-1"]');

    // Create Scan Job record
    const jobRes = await query(
      `INSERT INTO scan_jobs (organization_id, scan_category, cloud_account_id, status, progress, triggered_by)
       VALUES ($1, 'CLOUD_CSPM', $2, 'RUNNING', 25, $3)
       RETURNING *`,
      [req.user.organizationId, account.id, req.user.id]
    );
    const scanJob = jobRes.rows[0];

    const scanResult = await executeCloudPostureScan({
      provider: account.provider,
      accountIdentifier: account.account_identifier,
      authMethod: account.auth_method,
      credentials: decryptedCreds,
      regions,
      connectionMode: account.connection_mode
    });

    // Replace previous resource snapshot for this account
    await query('DELETE FROM cloud_resources WHERE cloud_account_id = $1', [account.id]);

    for (const r of scanResult.resources || []) {
      await query(
        `INSERT INTO cloud_resources
         (organization_id, cloud_account_id, provider, service_type, resource_type, resource_id, resource_name, region, is_public, encryption_enabled, configuration)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          req.user.organizationId,
          account.id,
          account.provider,
          r.service_type,
          r.resource_type,
          r.resource_id,
          r.resource_name,
          r.region,
          Boolean(r.is_public),
          Boolean(r.encryption_enabled),
          JSON.stringify(r.configuration || {})
        ]
      );
    }

    // Deduplicate and insert findings
    let insertedFindingsCount = 0;
    for (const f of scanResult.findings || []) {
      const existing = await query(
        `SELECT id FROM vulnerabilities
         WHERE organization_id = $1 AND cloud_account_id = $2 AND rule_id = $3 AND affected_asset = $4 AND status = 'OPEN'`,
        [req.user.organizationId, account.id, f.rule_id, f.affected_asset]
      );

      if (existing.rows.length > 0) {
        await query(
          'UPDATE vulnerabilities SET last_detected_at = NOW(), scan_job_id = $1 WHERE id = $2',
          [scanJob.id, existing.rows[0].id]
        );
      } else {
        await query(
          `INSERT INTO vulnerabilities
           (organization_id, scan_job_id, cloud_account_id, source_type, rule_id, title, description, category, severity, cvss_score, cwe_id, affected_asset, remediation_summary, compliance_controls, evidence)
           VALUES ($1, $2, $3, 'CLOUD_CSPM', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
          [
            req.user.organizationId,
            scanJob.id,
            account.id,
            f.rule_id,
            f.title,
            f.description,
            f.category,
            f.severity,
            f.cvss_score || 7.5,
            f.cwe_id || 'CWE-284',
            f.affected_asset,
            f.remediation_summary,
            JSON.stringify(f.compliance_controls || []),
            JSON.stringify(f.evidence || {})
          ]
        );
      }
      insertedFindingsCount += 1;
    }

    // Calculate security score for account
    const critCount = (scanResult.findings || []).filter((f) => f.severity === 'CRITICAL').length;
    const highCount = (scanResult.findings || []).filter((f) => f.severity === 'HIGH').length;
    const newScore = Math.max(15, 100 - critCount * 18 - highCount * 10);

    await query(
      'UPDATE cloud_accounts SET last_scanned_at = NOW(), security_score = $1 WHERE id = $2',
      [newScore, account.id]
    );

    await query(
      `UPDATE scan_jobs
       SET status = 'COMPLETED', progress = 100, findings_count = $1, completed_at = NOW(),
           summary = $2
       WHERE id = $3`,
      [
        insertedFindingsCount,
        JSON.stringify({
          provider: account.provider,
          discoveredResources: (scanResult.resources || []).length,
          findingsDetected: insertedFindingsCount,
          mode: scanResult.mode || account.connection_mode
        }),
        scanJob.id
      ]
    );

    // Recalculate ISO 27001 & SOC 2 compliance controls
    await recalculateComplianceStatus(req.user.organizationId);

    // Emit Socket.IO event if io is attached to app
    const io = req.app.get('io');
    if (io) {
      io.emit('cloud:scan_completed', {
        accountId: account.id,
        provider: account.provider,
        accountName: account.account_name,
        findingsCount: insertedFindingsCount,
        securityScore: newScore
      });
    }

    await logAuditEvent({
      organizationId: req.user.organizationId,
      userId: req.user.id,
      actorEmail: req.user.email,
      actorRole: req.user.role,
      action: 'CLOUD_POSTURE_SCAN_COMPLETED',
      resourceType: 'CLOUD_ACCOUNT',
      resourceId: account.id,
      ipAddress: req.clientIp || req.ip,
      details: {
        provider: account.provider,
        resourcesDiscovered: (scanResult.resources || []).length,
        findingsDetected: insertedFindingsCount
      }
    });

    return res.json({
      scanJobId: scanJob.id,
      accountId: account.id,
      provider: account.provider,
      mode: scanResult.mode || account.connection_mode,
      securityScore: newScore,
      resourcesDiscovered: (scanResult.resources || []).length,
      findingsDetected: insertedFindingsCount,
      resources: scanResult.resources,
      findings: scanResult.findings
    });
  } catch (err) {
    return res.status(400).json({ error: 'CLOUD_SCAN_FAILED', message: err.message });
  }
});

/**
 * GET /api/v1/cloud/resources
 * Lists all discovered cloud resources across AWS, Azure, and GCP.
 */
router.get('/resources', authenticateJWT, async (req, res) => {
  const providerFilter = req.query.provider;
  const params = [req.user.organizationId];
  let sql = `
    SELECT r.*, a.account_name, a.connection_mode
    FROM cloud_resources r
    JOIN cloud_accounts a ON r.cloud_account_id = a.id
    WHERE r.organization_id = $1
  `;
  if (providerFilter) {
    params.push(providerFilter.toUpperCase());
    sql += ` AND r.provider = $2`;
  }
  sql += ' ORDER BY r.discovered_at DESC';

  const result = await query(sql, params);
  return res.json({ resources: result.rows });
});

/**
 * DELETE /api/v1/cloud/accounts/:id
 * Removes a connected cloud account (Admin only).
 */
router.delete('/accounts/:id', authenticateJWT, requireRole('ADMIN'), async (req, res) => {
  const accountId = req.params.id;
  await query('DELETE FROM cloud_accounts WHERE id = $1 AND organization_id = $2', [
    accountId,
    req.user.organizationId
  ]);
  await recalculateComplianceStatus(req.user.organizationId);
  return res.json({ message: 'Cloud account disconnected and removed.' });
});

module.exports = router;
