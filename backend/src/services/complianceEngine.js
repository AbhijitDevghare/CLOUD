const { query } = require('../config/db');

/**
 * Dynamically re-evaluates all ISO/IEC 27001 and SOC 2 compliance controls for an organization
 * based on currently OPEN vulnerabilities and cloud misconfigurations.
 * @param {string} organizationId
 */
async function recalculateComplianceStatus(organizationId) {
  const openVulnsResult = await query(
    `SELECT id, category, source_type, severity, compliance_controls, affected_asset, title
     FROM vulnerabilities
     WHERE organization_id = $1 AND status = 'OPEN'`,
    [organizationId]
  );

  const openVulns = openVulnsResult.rows;
  const controlsResult = await query(
    `SELECT id, framework, control_code, mapped_rule_categories, evaluation_type
     FROM compliance_controls
     WHERE organization_id = $1`,
    [organizationId]
  );

  for (const ctrl of controlsResult.rows) {
    if (ctrl.evaluation_type === 'MANUAL') {
      continue;
    }

    const mappedCategories = Array.isArray(ctrl.mapped_rule_categories)
      ? ctrl.mapped_rule_categories
      : JSON.parse(ctrl.mapped_rule_categories || '[]');

    const matchingFailures = openVulns.filter((v) => {
      const explicitControls = Array.isArray(v.compliance_controls)
        ? v.compliance_controls
        : JSON.parse(v.compliance_controls || '[]');

      if (explicitControls.includes(ctrl.control_code)) {
        return true;
      }
      return (
        mappedCategories.includes(v.category) ||
        mappedCategories.includes(v.source_type)
      );
    });

    const failingCount = matchingFailures.length;
    let newStatus = 'PASSING';
    if (failingCount > 0) {
      const hasHighOrCrit = matchingFailures.some((f) =>
        ['CRITICAL', 'HIGH'].includes(f.severity)
      );
      newStatus = hasHighOrCrit ? 'FAILING' : 'PARTIAL';
    }

    await query(
      `UPDATE compliance_controls
       SET status = $1,
           failing_assets_count = $2,
           last_evaluated_at = NOW()
       WHERE id = $3`,
      [newStatus, failingCount, ctrl.id]
    );
  }
}

module.exports = {
  recalculateComplianceStatus
};
