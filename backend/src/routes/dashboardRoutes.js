const express = require('../utils/expressCompat');
const { query, getDbMode } = require('../config/db');
const { initRedis, getRedisMode } = require('../config/redis');
const { authenticateJWT } = require('../middleware/auth');
const { recalculateComplianceStatus } = require('../services/complianceEngine');
const { checkPythonServiceHealth } = require('../services/pythonBridge');

const router = express.Router();

/**
 * GET /api/v1/dashboard/overview
 * Section 5: Unified Command Center Dashboard endpoint aggregating:
 * - Overall Security Score (0-100)
 * - Total Cloud Accounts & Discovered Cloud Resources
 * - Critical & High Vulnerabilities + Severity Distribution
 * - Active Threats & Blocked Malicious IPs
 * - Compliance Readiness (ISO 27001 & SOC 2)
 * - Top AI-Prioritized Recommendations
 */
router.get('/overview', authenticateJWT, async (req, res) => {
  const orgId = req.user.organizationId;
  await recalculateComplianceStatus(orgId);

  const [
    cloudAccountsRes,
    cloudResourcesRes,
    targetsRes,
    openVulnsRes,
    threatsRes,
    pendingActionsRes,
    aiLogsRes,
    complianceRes,
    recentAuditRes,
    redis,
    pythonHealth
  ] = await Promise.all([
    query('SELECT id, provider, account_name, security_score, connection_mode, status FROM cloud_accounts WHERE organization_id = $1', [orgId]),
    query('SELECT provider, is_public, encryption_enabled FROM cloud_resources WHERE organization_id = $1', [orgId]),
    query('SELECT id, name, target_type, is_verified, security_score FROM scan_targets WHERE organization_id = $1', [orgId]),
    query('SELECT id, title, severity, cvss_score, source_type, category, affected_asset, remediation_summary, status, last_detected_at FROM vulnerabilities WHERE organization_id = $1', [orgId]),
    query('SELECT * FROM threat_alerts WHERE organization_id = $1 ORDER BY last_seen_at DESC LIMIT 15', [orgId]),
    query("SELECT * FROM prevention_actions WHERE organization_id = $1 AND status = 'PENDING_APPROVAL' ORDER BY created_at DESC", [orgId]),
    query('SELECT verdict, risk_score FROM ai_security_logs WHERE organization_id = $1', [orgId]),
    query('SELECT framework, status FROM compliance_controls WHERE organization_id = $1', [orgId]),
    query('SELECT id, actor_email, actor_role, action, resource_type, status, created_at FROM audit_logs WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 8', [orgId]),
    initRedis(),
    checkPythonServiceHealth()
  ]);

  const blockedIps = await redis.smembers('active_blocked_ips');
  const allVulns = openVulnsRes.rows;
  const openVulns = allVulns.filter((v) => v.status === 'OPEN');

  const severityDistribution = {
    CRITICAL: openVulns.filter((v) => v.severity === 'CRITICAL').length,
    HIGH: openVulns.filter((v) => v.severity === 'HIGH').length,
    MEDIUM: openVulns.filter((v) => v.severity === 'MEDIUM').length,
    LOW: openVulns.filter((v) => v.severity === 'LOW').length,
    INFO: openVulns.filter((v) => v.severity === 'INFO').length
  };

  const activeThreats = threatsRes.rows.filter((t) => t.status === 'ACTIVE');

  // Compute composite security score (0-100)
  const vulnPenalty =
    severityDistribution.CRITICAL * 10 +
    severityDistribution.HIGH * 5 +
    severityDistribution.MEDIUM * 2;
  const threatPenalty = activeThreats.length * 6;
  const overallSecurityScore = Math.max(18, Math.min(100, 100 - vulnPenalty - threatPenalty));

  // Compliance readiness percentages
  const calcFrameworkPct = (fw) => {
    const list = complianceRes.rows.filter((c) => c.framework === fw);
    if (list.length === 0) return 100;
    const passing = list.filter((c) => c.status === 'PASSING').length;
    const partial = list.filter((c) => c.status === 'PARTIAL').length;
    return Math.round(((passing + partial * 0.5) / list.length) * 100);
  };

  // Cloud status by provider
  const cloudByProvider = ['AWS', 'AZURE', 'GCP'].map((prov) => {
    const accounts = cloudAccountsRes.rows.filter((a) => a.provider === prov);
    const resources = cloudResourcesRes.rows.filter((r) => r.provider === prov);
    return {
      provider: prov,
      connectedAccounts: accounts.length,
      totalResources: resources.length,
      publicResources: resources.filter((r) => r.is_public).length
    };
  });

  return res.json({
    kpis: {
      overallSecurityScore,
      connectedCloudAccounts: cloudAccountsRes.rows.length,
      totalCloudResources: cloudResourcesRes.rows.length,
      monitoredWebAndApiTargets: targetsRes.rows.length,
      openVulnerabilitiesCount: openVulns.length,
      criticalFindingsCount: severityDistribution.CRITICAL,
      highFindingsCount: severityDistribution.HIGH,
      activeThreatsCount: activeThreats.length,
      pendingApprovalsCount: pendingActionsRes.rows.length,
      blockedIpsCount: blockedIps.length,
      aiInspectionsCount: aiLogsRes.rows.length,
      aiBlockedPromptsCount: aiLogsRes.rows.filter((l) => l.verdict === 'BLOCKED' || l.verdict === 'REDACTED').length
    },
    severityDistribution,
    cloudByProvider,
    complianceReadiness: {
      ISO_27001: calcFrameworkPct('ISO_27001'),
      SOC_2: calcFrameworkPct('SOC_2')
    },
    topPriorityFindings: openVulns.slice(0, 5),
    recentThreats: threatsRes.rows.slice(0, 6),
    pendingPreventionApprovals: pendingActionsRes.rows,
    recentAuditLogs: recentAuditRes.rows,
    systemHealth: {
      databaseMode: getDbMode(),
      redisMode: getRedisMode(),
      pythonServiceOnline: pythonHealth.online,
      pythonServiceDetails: pythonHealth.details
    }
  });
});

module.exports = router;
