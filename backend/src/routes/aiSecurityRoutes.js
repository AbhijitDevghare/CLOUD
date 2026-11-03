const express = require('../utils/expressCompat');
const { query } = require('../config/db');
const { authenticateJWT, requireRole } = require('../middleware/auth');
const {
  generateAiSecurityAnalysis,
  inspectAiApplicationPayload
} = require('../services/pythonBridge');
const { logAuditEvent } = require('../services/auditService');

const router = express.Router();

/**
 * POST /api/v1/ai-security/analyze-finding/:id
 * Module 6: Generates or retrieves cached AI-Powered Security Analysis & Remediation Playbook
 * for a specific vulnerability or cloud misconfiguration finding.
 */
router.post('/analyze-finding/:id', authenticateJWT, async (req, res) => {
  try {
    const findingId = req.params.id;
    const vulnRes = await query(
      'SELECT * FROM vulnerabilities WHERE id = $1 AND organization_id = $2',
      [findingId, req.user.organizationId]
    );

    if (vulnRes.rows.length === 0) {
      return res.status(404).json({ error: 'FINDING_NOT_FOUND', message: 'Vulnerability finding not found.' });
    }

    const finding = vulnRes.rows[0];
    if (finding.ai_analysis && Object.keys(finding.ai_analysis).length > 0 && !req.body.forceRefresh) {
      return res.json({
        findingId: finding.id,
        cached: true,
        analysis: finding.ai_analysis
      });
    }

    const analysis = await generateAiSecurityAnalysis(finding);

    await query(
      'UPDATE vulnerabilities SET ai_analysis = $1 WHERE id = $2',
      [JSON.stringify(analysis), finding.id]
    );

    return res.json({
      findingId: finding.id,
      cached: false,
      analysis
    });
  } catch (err) {
    return res.status(500).json({ error: 'AI_ANALYSIS_ERROR', message: err.message });
  }
});

/**
 * GET /api/v1/ai-security/prioritized-risks
 * Module 6: Returns AI-prioritized top security findings combining CVSS severity, public exposure,
 * and active threat correlation.
 */
router.get('/prioritized-risks', authenticateJWT, async (req, res) => {
  const openVulnsRes = await query(
    `SELECT * FROM vulnerabilities
     WHERE organization_id = $1 AND status = 'OPEN'
     ORDER BY cvss_score DESC, last_detected_at DESC
     LIMIT 10`,
    [req.user.organizationId]
  );

  const prioritized = [];
  for (const v of openVulnsRes.rows) {
    let aiData = v.ai_analysis;
    if (!aiData || Object.keys(aiData).length === 0) {
      aiData = await generateAiSecurityAnalysis(v);
      await query('UPDATE vulnerabilities SET ai_analysis = $1 WHERE id = $2', [
        JSON.stringify(aiData),
        v.id
      ]);
    }
    prioritized.push({
      ...v,
      ai_analysis: aiData
    });
  }

  return res.json({ prioritizedRisks: prioritized });
});

/**
 * POST /api/v1/ai-security/inspect
 * Module 7: AI Application Security Guardrail & OWASP LLM Top 10 Inspection Endpoint.
 * Detects Prompt Injection (LLM01), API Key & Secret Leakage (LLM02), PII Exposure (LLM02),
 * and Unsafe Executable Output / XSS (LLM05). Automatically redacts secrets before database persistence.
 */
router.post('/inspect', authenticateJWT, requireRole('ADMIN', 'ANALYST'), async (req, res) => {
  try {
    const {
      applicationName = 'Enterprise Customer Support LLM',
      stage = 'FULL_INTERACTION',
      prompt = '',
      response = ''
    } = req.body;

    if (!prompt && !response) {
      return res.status(400).json({ error: 'EMPTY_PAYLOAD', message: 'Either prompt or response must be provided for inspection.' });
    }

    const inspectionResult = await inspectAiApplicationPayload({
      prompt,
      response,
      stage
    });

    const insertRes = await query(
      `INSERT INTO ai_security_logs
       (organization_id, application_name, inspection_stage, verdict, risk_score, owasp_llm_categories, detected_violations, sanitized_prompt, sanitized_response, latency_ms, source_ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [
        req.user.organizationId,
        applicationName,
        stage,
        inspectionResult.verdict,
        inspectionResult.risk_score,
        JSON.stringify(inspectionResult.owasp_llm_categories || []),
        JSON.stringify(inspectionResult.detected_violations || []),
        inspectionResult.sanitized_prompt,
        inspectionResult.sanitized_response,
        inspectionResult.latency_ms || 4,
        req.clientIp || req.ip || '127.0.0.1'
      ]
    );

    const logEntry = insertRes.rows[0];

    const io = req.app.get('io');
    if (io && inspectionResult.verdict !== 'ALLOWED') {
      io.emit('ai_security:violation_detected', logEntry);
    }

    await logAuditEvent({
      organizationId: req.user.organizationId,
      userId: req.user.id,
      actorEmail: req.user.email,
      actorRole: req.user.role,
      action: 'AI_GUARDRAIL_INSPECTION',
      resourceType: 'AI_APPLICATION',
      resourceId: logEntry.id,
      ipAddress: req.clientIp || req.ip,
      details: {
        applicationName,
        verdict: inspectionResult.verdict,
        riskScore: inspectionResult.risk_score,
        owaspCategories: inspectionResult.owasp_llm_categories
      }
    });

    return res.json({
      inspectionId: logEntry.id,
      applicationName,
      ...inspectionResult
    });
  } catch (err) {
    return res.status(500).json({ error: 'AI_GUARDRAIL_ERROR', message: err.message });
  }
});

/**
 * GET /api/v1/ai-security/logs
 * Module 7: Returns historical AI Application Guardrail inspection logs and OWASP LLM violation stats.
 */
router.get('/logs', authenticateJWT, async (req, res) => {
  const logsRes = await query(
    `SELECT * FROM ai_security_logs
     WHERE organization_id = $1
     ORDER BY created_at DESC
     LIMIT 100`,
    [req.user.organizationId]
  );

  const logs = logsRes.rows;
  const stats = {
    totalInspected: logs.length,
    blockedCount: logs.filter((l) => l.verdict === 'BLOCKED').length,
    redactedCount: logs.filter((l) => l.verdict === 'REDACTED').length,
    allowedCount: logs.filter((l) => l.verdict === 'ALLOWED').length
  };

  return res.json({ stats, logs });
});

module.exports = router;
