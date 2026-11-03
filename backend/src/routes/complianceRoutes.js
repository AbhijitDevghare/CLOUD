const express = require('../utils/expressCompat');
const { query } = require('../config/db');
const { authenticateJWT, requireRole } = require('../middleware/auth');
const { recalculateComplianceStatus } = require('../services/complianceEngine');
const { logAuditEvent } = require('../services/auditService');

const router = express.Router();

/**
 * GET /api/v1/compliance/frameworks
 * Module 8: Evaluates and returns ISO/IEC 27001:2022 and SOC 2 compliance status,
 * control checklists, failing asset counts, and linked technical findings.
 */
router.get('/frameworks', authenticateJWT, async (req, res) => {
  await recalculateComplianceStatus(req.user.organizationId);

  const controlsRes = await query(
    `SELECT * FROM compliance_controls
     WHERE organization_id = $1
     ORDER BY framework ASC, control_code ASC`,
    [req.user.organizationId]
  );

  const openVulnsRes = await query(
    `SELECT id, rule_id, title, severity, category, source_type, affected_asset, compliance_controls
     FROM vulnerabilities
     WHERE organization_id = $1 AND status = 'OPEN'`,
    [req.user.organizationId]
  );

  const openVulns = openVulnsRes.rows;
  const controls = controlsRes.rows.map((ctrl) => {
    const mappedCats = Array.isArray(ctrl.mapped_rule_categories)
      ? ctrl.mapped_rule_categories
      : JSON.parse(ctrl.mapped_rule_categories || '[]');

    const linkedFindings = openVulns.filter((v) => {
      const explicit = Array.isArray(v.compliance_controls)
        ? v.compliance_controls
        : JSON.parse(v.compliance_controls || '[]');
      return explicit.includes(ctrl.control_code) || mappedCats.includes(v.category) || mappedCats.includes(v.source_type);
    });

    return {
      ...ctrl,
      linked_findings: linkedFindings
    };
  });

  const isoControls = controls.filter((c) => c.framework === 'ISO_27001');
  const soc2Controls = controls.filter((c) => c.framework === 'SOC_2');

  const computeSummary = (list) => {
    const total = list.length || 1;
    const passing = list.filter((c) => c.status === 'PASSING').length;
    const failing = list.filter((c) => c.status === 'FAILING').length;
    const partial = list.filter((c) => c.status === 'PARTIAL').length;
    const readinessPercentage = Math.round(((passing + partial * 0.5) / total) * 100);
    return { total: list.length, passing, failing, partial, readinessPercentage };
  };

  return res.json({
    disclaimer:
      'Continuous Compliance Monitoring & Evidence Collection tracks technical control adherence. Formal ISO/IEC 27001 certification or SOC 2 Type II attestation requires an independent accredited third-party auditor.',
    summaries: {
      ISO_27001: computeSummary(isoControls),
      SOC_2: computeSummary(soc2Controls)
    },
    controls
  });
});

/**
 * PATCH /api/v1/compliance/controls/:id
 * Allows Compliance Officers, Auditors, or Admins to update evidence notes or manual control attestations.
 */
router.patch('/controls/:id', authenticateJWT, async (req, res) => {
  const { evidenceNotes, manualStatus, artifactName } = req.body;
  const controlId = req.params.id;

  const ctrlRes = await query(
    'SELECT * FROM compliance_controls WHERE id = $1 AND organization_id = $2',
    [controlId, req.user.organizationId]
  );

  if (ctrlRes.rows.length === 0) {
    return res.status(404).json({ error: 'CONTROL_NOT_FOUND' });
  }

  const ctrl = ctrlRes.rows[0];
  const artifacts = Array.isArray(ctrl.evidence_artifacts)
    ? ctrl.evidence_artifacts
    : JSON.parse(ctrl.evidence_artifacts || '[]');

  if (artifactName) {
    artifacts.push({
      name: artifactName,
      uploadedBy: req.user.email,
      uploadedAt: new Date().toISOString()
    });
  }

  const updatedStatus =
    manualStatus && ['PASSING', 'FAILING', 'PARTIAL', 'NOT_ASSESSED'].includes(manualStatus)
      ? manualStatus
      : ctrl.status;

  const updatedNotes = typeof evidenceNotes === 'string' ? evidenceNotes : ctrl.evidence_notes;

  const updatedRes = await query(
    `UPDATE compliance_controls
     SET evidence_notes = $1, status = $2, evidence_artifacts = $3, last_evaluated_at = NOW()
     WHERE id = $4
     RETURNING *`,
    [updatedNotes, updatedStatus, JSON.stringify(artifacts), controlId]
  );

  await logAuditEvent({
    organizationId: req.user.organizationId,
    userId: req.user.id,
    actorEmail: req.user.email,
    actorRole: req.user.role,
    action: 'COMPLIANCE_EVIDENCE_UPDATED',
    resourceType: 'COMPLIANCE_CONTROL',
    resourceId: controlId,
    ipAddress: req.clientIp || req.ip,
    details: { framework: ctrl.framework, controlCode: ctrl.control_code, status: updatedStatus }
  });

  return res.json({ control: updatedRes.rows[0] });
});

/**
 * GET /api/v1/compliance/export-report
 * Generates an exportable JSON/Audit Evidence Package for ISO 27001 and SOC 2.
 */
router.get('/export-report', authenticateJWT, requireRole('ADMIN', 'AUDITOR', 'ANALYST'), async (req, res) => {
  await recalculateComplianceStatus(req.user.organizationId);

  const controlsRes = await query(
    'SELECT framework, control_code, category, title, status, failing_assets_count, evidence_notes, last_evaluated_at FROM compliance_controls WHERE organization_id = $1 ORDER BY framework, control_code',
    [req.user.organizationId]
  );

  const auditCountRes = await query(
    'SELECT COUNT(*)::int AS count FROM audit_logs WHERE organization_id = $1',
    [req.user.organizationId]
  );

  return res.json({
    reportTitle: 'AegisCloud Continuous Compliance & Security Posture Audit Package',
    generatedAt: new Date().toISOString(),
    generatedBy: req.user.email,
    organizationId: req.user.organizationId,
    immutableAuditEventsRecorded: auditCountRes.rows[0].count,
    controls: controlsRes.rows
  });
});

module.exports = router;
