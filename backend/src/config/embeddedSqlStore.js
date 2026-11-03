const crypto = require('crypto');

/**
 * Embedded Relational & JSONB SQL Engine for AegisCloud.
 * Executes parameterized PostgreSQL queries when neither a live PostgreSQL server
 * nor pg-mem node_modules is installed locally.
 */
class EmbeddedPostgresEngine {
  constructor() {
    this.tables = {
      organizations: [],
      users: [],
      user_sessions: [],
      audit_logs: [],
      cloud_accounts: [],
      cloud_resources: [],
      scan_targets: [],
      scan_jobs: [],
      vulnerabilities: [],
      threat_alerts: [],
      prevention_actions: [],
      ip_safelist: [],
      ai_security_logs: [],
      compliance_controls: []
    };
  }

  _now() {
    return new Date().toISOString();
  }

  _parseJsonSafe(val, fallback) {
    if (val === undefined || val === null) return fallback;
    if (typeof val === 'object') return val;
    try {
      return JSON.parse(val);
    } catch {
      return fallback;
    }
  }

  async query(sqlText, params = []) {
    const sql = sqlText.replace(/\s+/g, ' ').trim();
    const upper = sql.toUpperCase();

    // 1. Organizations
    if (upper.startsWith('INSERT INTO ORGANIZATIONS')) {
      const [id, name, slug, tier] = params;
      if (!this.tables.organizations.some((o) => o.slug === slug || o.id === id)) {
        this.tables.organizations.push({
          id: id || crypto.randomUUID(),
          name,
          slug,
          subscription_tier: tier || 'ENTERPRISE',
          created_at: this._now(),
          updated_at: this._now()
        });
      }
      return { rows: [] };
    }

    // 2. Users Count
    if (upper.includes('SELECT COUNT(*)::INT AS COUNT FROM USERS')) {
      const orgId = params[0];
      const count = this.tables.users.filter((u) => u.organization_id === orgId).length;
      return { rows: [{ count }] };
    }

    // 3. Seed Users Batch Insert
    if (upper.startsWith('INSERT INTO USERS (ID, ORGANIZATION_ID, EMAIL')) {
      const [id1, orgId, hash1, id2, hash2, id3, hash3] = params;
      this.tables.users.push(
        {
          id: id1,
          organization_id: orgId,
          email: 'admin@aegiscloud.io',
          password_hash: hash1,
          full_name: 'Elena Vance (Platform Admin)',
          role: 'ADMIN',
          is_active: true,
          mfa_enabled: true,
          failed_login_attempts: 0,
          locked_until: null,
          last_login_at: null,
          last_login_ip: '127.0.0.1',
          created_at: this._now()
        },
        {
          id: id2,
          organization_id: orgId,
          email: 'analyst@aegiscloud.io',
          password_hash: hash2,
          full_name: 'Marcus Chen (Senior SOC Analyst)',
          role: 'ANALYST',
          is_active: true,
          mfa_enabled: false,
          failed_login_attempts: 0,
          locked_until: null,
          last_login_at: null,
          last_login_ip: '127.0.0.1',
          created_at: this._now()
        },
        {
          id: id3,
          organization_id: orgId,
          email: 'auditor@aegiscloud.io',
          password_hash: hash3,
          full_name: 'Priya Nair (Compliance & GRC Auditor)',
          role: 'AUDITOR',
          is_active: true,
          mfa_enabled: false,
          failed_login_attempts: 0,
          locked_until: null,
          last_login_at: null,
          last_login_ip: '127.0.0.1',
          created_at: this._now()
        }
      );
      return { rows: [] };
    }

    // 4. Register Single User
    if (upper.startsWith('INSERT INTO USERS (ORGANIZATION_ID, EMAIL')) {
      const [orgId, email, passwordHash, fullName, role] = params;
      const newUser = {
        id: crypto.randomUUID(),
        organization_id: orgId,
        email,
        password_hash: passwordHash,
        full_name: fullName,
        role,
        is_active: true,
        mfa_enabled: false,
        failed_login_attempts: 0,
        locked_until: null,
        last_login_at: null,
        last_login_ip: null,
        created_at: this._now()
      };
      this.tables.users.push(newUser);
      return { rows: [newUser] };
    }

    // 5. Select User by Email or ID
    if (upper.includes('FROM USERS WHERE EMAIL = $1')) {
      const found = this.tables.users.filter((u) => u.email === params[0]);
      return { rows: found };
    }
    if (upper.includes('FROM USERS WHERE ID = $1 AND ORGANIZATION_ID = $2')) {
      const found = this.tables.users.filter((u) => u.id === params[0] && u.organization_id === params[1]);
      return { rows: found };
    }
    if (upper.includes('FROM USERS WHERE ID = $1')) {
      const found = this.tables.users.filter((u) => u.id === params[0]);
      return { rows: found };
    }
    if (upper.includes('FROM USERS WHERE ORGANIZATION_ID = $1')) {
      const found = this.tables.users.filter((u) => u.organization_id === params[0]);
      return { rows: found };
    }

    // 6. Update User Login / Lockout / Role
    if (upper.startsWith('UPDATE USERS SET FAILED_LOGIN_ATTEMPTS = $1, LOCKED_UNTIL = $2 WHERE ID = $3')) {
      const u = this.tables.users.find((x) => x.id === params[2]);
      if (u) {
        u.failed_login_attempts = params[0];
        u.locked_until = params[1];
      }
      return { rows: [] };
    }
    if (upper.startsWith('UPDATE USERS SET FAILED_LOGIN_ATTEMPTS = 0')) {
      const u = this.tables.users.find((x) => x.id === params[1]);
      if (u) {
        u.failed_login_attempts = 0;
        u.locked_until = null;
        u.last_login_at = this._now();
        u.last_login_ip = params[0];
      }
      return { rows: [] };
    }
    if (upper.startsWith('UPDATE USERS SET ROLE = $1, IS_ACTIVE = $2')) {
      const u = this.tables.users.find((x) => x.id === params[2]);
      if (u) {
        u.role = params[0];
        u.is_active = params[1];
      }
      return { rows: [] };
    }

    // 7. User Sessions
    if (upper.startsWith('INSERT INTO USER_SESSIONS')) {
      this.tables.user_sessions.push({
        id: crypto.randomUUID(),
        user_id: params[0],
        refresh_token_hash: params[1],
        ip_address: params[2],
        user_agent: params[3],
        is_revoked: false,
        expires_at: params[4],
        created_at: this._now()
      });
      return { rows: [] };
    }
    if (upper.startsWith('UPDATE USER_SESSIONS SET IS_REVOKED = TRUE')) {
      this.tables.user_sessions.forEach((s) => {
        if (s.user_id === params[0]) s.is_revoked = true;
      });
      return { rows: [] };
    }

    // 8. IP Safelist
    if (upper.startsWith('INSERT INTO IP_SAFELIST')) {
      const orgId = params[0];
      if (this.tables.ip_safelist.length === 0) {
        this.tables.ip_safelist.push(
          { id: crypto.randomUUID(), organization_id: orgId, ip_cidr: '127.0.0.1/32', label: 'Local Loopback Interface', created_at: this._now() },
          { id: crypto.randomUUID(), organization_id: orgId, ip_cidr: '10.0.0.0/8', label: 'Internal VPC Private Network', created_at: this._now() },
          { id: crypto.randomUUID(), organization_id: orgId, ip_cidr: '198.51.100.10/32', label: 'Corporate VPN Gateway Egress', created_at: this._now() }
        );
      }
      return { rows: [] };
    }
    if (upper.includes('FROM IP_SAFELIST WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.ip_safelist.filter((s) => s.organization_id === params[0]) };
    }

    // 9. Audit Logs
    if (upper.startsWith('INSERT INTO AUDIT_LOGS')) {
      const entry = {
        id: crypto.randomUUID(),
        organization_id: params[0],
        user_id: params[1],
        actor_email: params[2],
        actor_role: params[3],
        action: params[4],
        resource_type: params[5],
        resource_id: params[6],
        ip_address: params[7],
        user_agent: params[8],
        status: params[9],
        details: this._parseJsonSafe(params[10], {}),
        created_at: this._now()
      };
      this.tables.audit_logs.unshift(entry);
      return { rows: [entry] };
    }
    if (upper.includes('SELECT COUNT(*)::INT AS COUNT FROM AUDIT_LOGS')) {
      const count = this.tables.audit_logs.filter((a) => a.organization_id === params[0]).length;
      return { rows: [{ count }] };
    }
    if (upper.includes('FROM AUDIT_LOGS WHERE ORGANIZATION_ID = $1 AND USER_ID = $2')) {
      const rows = this.tables.audit_logs
        .filter((a) => a.organization_id === params[0] && a.user_id === params[1])
        .slice(0, params[2] || 100);
      return { rows };
    }
    if (upper.includes('FROM AUDIT_LOGS WHERE ORGANIZATION_ID = $1')) {
      const limit = params[1] || 100;
      const rows = this.tables.audit_logs.filter((a) => a.organization_id === params[0]).slice(0, limit);
      return { rows };
    }

    // 10. Cloud Accounts & Resources
    if (upper.startsWith('INSERT INTO CLOUD_ACCOUNTS')) {
      const acc = {
        id: crypto.randomUUID(),
        organization_id: params[0],
        provider: params[1],
        account_name: params[2],
        account_identifier: params[3],
        auth_method: params[4],
        encrypted_credentials: params[5],
        regions: this._parseJsonSafe(params[6], ['us-east-1']),
        connection_mode: params[7],
        status: 'CONNECTED',
        last_scanned_at: null,
        security_score: 100,
        created_by: params[8],
        created_at: this._now()
      };
      this.tables.cloud_accounts.unshift(acc);
      return { rows: [acc] };
    }
    if (upper.includes('FROM CLOUD_ACCOUNTS WHERE ID = $1 AND ORGANIZATION_ID = $2')) {
      return {
        rows: this.tables.cloud_accounts.filter((a) => a.id === params[0] && a.organization_id === params[1])
      };
    }
    if (upper.includes('FROM CLOUD_ACCOUNTS WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.cloud_accounts.filter((a) => a.organization_id === params[0]) };
    }
    if (upper.startsWith('UPDATE CLOUD_ACCOUNTS SET LAST_SCANNED_AT')) {
      const acc = this.tables.cloud_accounts.find((a) => a.id === params[1]);
      if (acc) {
        acc.last_scanned_at = this._now();
        acc.security_score = params[0];
      }
      return { rows: [] };
    }
    if (upper.startsWith('DELETE FROM CLOUD_ACCOUNTS')) {
      this.tables.cloud_accounts = this.tables.cloud_accounts.filter(
        (a) => !(a.id === params[0] && a.organization_id === params[1])
      );
      this.tables.cloud_resources = this.tables.cloud_resources.filter((r) => r.cloud_account_id !== params[0]);
      this.tables.vulnerabilities = this.tables.vulnerabilities.filter((v) => v.cloud_account_id !== params[0]);
      return { rows: [] };
    }
    if (upper.startsWith('DELETE FROM CLOUD_RESOURCES WHERE CLOUD_ACCOUNT_ID = $1')) {
      this.tables.cloud_resources = this.tables.cloud_resources.filter((r) => r.cloud_account_id !== params[0]);
      return { rows: [] };
    }
    if (upper.startsWith('INSERT INTO CLOUD_RESOURCES')) {
      const resRow = {
        id: crypto.randomUUID(),
        organization_id: params[0],
        cloud_account_id: params[1],
        provider: params[2],
        service_type: params[3],
        resource_type: params[4],
        resource_id: params[5],
        resource_name: params[6],
        region: params[7],
        is_public: Boolean(params[8]),
        encryption_enabled: Boolean(params[9]),
        configuration: this._parseJsonSafe(params[10], {}),
        discovered_at: this._now()
      };
      this.tables.cloud_resources.push(resRow);
      return { rows: [resRow] };
    }
    if (upper.includes('SELECT CLOUD_ACCOUNT_ID, COUNT(*)::INT AS RESOURCE_COUNT FROM CLOUD_RESOURCES')) {
      const counts = {};
      for (const r of this.tables.cloud_resources.filter((x) => x.organization_id === params[0])) {
        counts[r.cloud_account_id] = (counts[r.cloud_account_id] || 0) + 1;
      }
      return {
        rows: Object.entries(counts).map(([cloud_account_id, resource_count]) => ({
          cloud_account_id,
          resource_count
        }))
      };
    }
    if (upper.includes('FROM CLOUD_RESOURCES R JOIN CLOUD_ACCOUNTS A')) {
      let rows = this.tables.cloud_resources.filter((r) => r.organization_id === params[0]);
      if (params[1]) {
        rows = rows.filter((r) => r.provider === params[1]);
      }
      return {
        rows: rows.map((r) => {
          const acc = this.tables.cloud_accounts.find((a) => a.id === r.cloud_account_id);
          return {
            ...r,
            account_name: acc?.account_name || 'Cloud Account',
            connection_mode: acc?.connection_mode || 'DEMO_SIMULATION'
          };
        })
      };
    }
    if (upper.includes('FROM CLOUD_RESOURCES WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.cloud_resources.filter((r) => r.organization_id === params[0]) };
    }

    // 11. Scan Targets & Scan Jobs
    if (upper.startsWith('INSERT INTO SCAN_TARGETS')) {
      const t = {
        id: crypto.randomUUID(),
        organization_id: params[0],
        name: params[1],
        target_type: params[2],
        target_url: params[3],
        verification_token: params[4],
        verification_method: params[5],
        is_verified: Boolean(params[6]),
        verified_at: params[7],
        environment: params[8],
        last_scanned_at: null,
        security_score: 100,
        created_at: this._now()
      };
      this.tables.scan_targets.unshift(t);
      return { rows: [t] };
    }
    if (upper.includes('FROM SCAN_TARGETS WHERE ID = $1 AND ORGANIZATION_ID = $2')) {
      return {
        rows: this.tables.scan_targets.filter((t) => t.id === params[0] && t.organization_id === params[1])
      };
    }
    if (upper.includes('FROM SCAN_TARGETS WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.scan_targets.filter((t) => t.organization_id === params[0]) };
    }
    if (upper.startsWith('UPDATE SCAN_TARGETS SET IS_VERIFIED = TRUE')) {
      const t = this.tables.scan_targets.find((x) => x.id === params[0]);
      if (t) {
        t.is_verified = true;
        t.verified_at = this._now();
      }
      return { rows: [] };
    }
    if (upper.startsWith('UPDATE SCAN_TARGETS SET LAST_SCANNED_AT')) {
      const t = this.tables.scan_targets.find((x) => x.id === params[1]);
      if (t) {
        t.last_scanned_at = this._now();
        t.security_score = params[0];
      }
      return { rows: [] };
    }

    if (upper.startsWith('INSERT INTO SCAN_JOBS')) {
      const isCloud = upper.includes('CLOUD_ACCOUNT_ID');
      const job = {
        id: crypto.randomUUID(),
        organization_id: params[0],
        scan_category: isCloud ? 'CLOUD_CSPM' : params[1],
        cloud_account_id: isCloud ? params[1] : null,
        target_id: isCloud ? null : params[2],
        status: 'RUNNING',
        progress: 25,
        findings_count: 0,
        summary: {},
        triggered_by: isCloud ? params[2] : params[3],
        started_at: this._now(),
        completed_at: null
      };
      this.tables.scan_jobs.unshift(job);
      return { rows: [job] };
    }
    if (upper.startsWith('UPDATE SCAN_JOBS SET STATUS')) {
      const job = this.tables.scan_jobs.find((j) => j.id === params[2]);
      if (job) {
        job.status = 'COMPLETED';
        job.progress = 100;
        job.findings_count = params[0];
        job.summary = this._parseJsonSafe(params[1], {});
        job.completed_at = this._now();
      }
      return { rows: [] };
    }
    if (upper.includes('FROM SCAN_JOBS WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.scan_jobs.filter((j) => j.organization_id === params[0]) };
    }

    // 12. Vulnerabilities
    if (upper.includes('FROM VULNERABILITIES WHERE ORGANIZATION_ID = $1 AND CLOUD_ACCOUNT_ID = $2 AND RULE_ID = $3')) {
      const found = this.tables.vulnerabilities.filter(
        (v) =>
          v.organization_id === params[0] &&
          v.cloud_account_id === params[1] &&
          v.rule_id === params[2] &&
          v.affected_asset === params[3] &&
          v.status === 'OPEN'
      );
      return { rows: found };
    }
    if (upper.startsWith('UPDATE VULNERABILITIES SET LAST_DETECTED_AT')) {
      const v = this.tables.vulnerabilities.find((x) => x.id === params[1]);
      if (v) {
        v.last_detected_at = this._now();
        v.scan_job_id = params[0];
      }
      return { rows: [] };
    }
    if (upper.startsWith('INSERT INTO VULNERABILITIES')) {
      const isCloudCspm = upper.includes("'CLOUD_CSPM'");
      let v;
      if (isCloudCspm) {
        v = {
          id: crypto.randomUUID(),
          organization_id: params[0],
          scan_job_id: params[1],
          cloud_account_id: params[2],
          target_id: null,
          source_type: 'CLOUD_CSPM',
          rule_id: params[3],
          title: params[4],
          description: params[5],
          category: params[6],
          severity: params[7],
          cvss_score: Number(params[8]),
          cve_id: null,
          cwe_id: params[9],
          affected_asset: params[10],
          status: 'OPEN',
          remediation_summary: params[11],
          compliance_controls: this._parseJsonSafe(params[12], []),
          evidence: this._parseJsonSafe(params[13], {}),
          ai_analysis: null,
          first_detected_at: this._now(),
          last_detected_at: this._now(),
          resolved_at: null
        };
      } else {
        v = {
          id: crypto.randomUUID(),
          organization_id: params[0],
          scan_job_id: params[1],
          cloud_account_id: null,
          target_id: params[2],
          source_type: params[3],
          rule_id: params[4],
          title: params[5],
          description: params[6],
          category: params[7],
          severity: params[8],
          cvss_score: Number(params[9]),
          cve_id: params[10],
          cwe_id: params[11],
          affected_asset: params[12],
          status: 'OPEN',
          remediation_summary: params[13],
          compliance_controls: this._parseJsonSafe(params[14], []),
          evidence: this._parseJsonSafe(params[15], {}),
          ai_analysis: null,
          first_detected_at: this._now(),
          last_detected_at: this._now(),
          resolved_at: null
        };
      }
      this.tables.vulnerabilities.push(v);
      return { rows: [v] };
    }
    if (upper.includes('FROM VULNERABILITIES WHERE ID = $1 AND ORGANIZATION_ID = $2')) {
      return {
        rows: this.tables.vulnerabilities.filter((v) => v.id === params[0] && v.organization_id === params[1])
      };
    }
    if (upper.startsWith('UPDATE VULNERABILITIES SET AI_ANALYSIS = $1 WHERE ID = $2')) {
      const v = this.tables.vulnerabilities.find((x) => x.id === params[1]);
      if (v) {
        v.ai_analysis = this._parseJsonSafe(params[0], {});
      }
      return { rows: [] };
    }
    if (upper.startsWith('UPDATE VULNERABILITIES SET STATUS = $1, RESOLVED_AT = $2')) {
      const v = this.tables.vulnerabilities.find((x) => x.id === params[2] && x.organization_id === params[3]);
      if (v) {
        v.status = params[0];
        v.resolved_at = params[1];
      }
      return { rows: [] };
    }
    if (upper.includes("FROM VULNERABILITIES WHERE ORGANIZATION_ID = $1 AND STATUS = 'OPEN'")) {
      const rows = this.tables.vulnerabilities
        .filter((v) => v.organization_id === params[0] && v.status === 'OPEN')
        .sort((a, b) => b.cvss_score - a.cvss_score);
      return { rows };
    }
    if (upper.includes('FROM VULNERABILITIES WHERE ORGANIZATION_ID = $1')) {
      const rows = this.tables.vulnerabilities
        .filter((v) => v.organization_id === params[0])
        .sort((a, b) => b.cvss_score - a.cvss_score);
      return { rows };
    }

    // 13. Threat Alerts & Prevention Actions
    if (upper.includes("FROM THREAT_ALERTS WHERE ORGANIZATION_ID = $1 AND SOURCE_IP = $2 AND THREAT_TYPE = $3")) {
      const rows = this.tables.threat_alerts.filter(
        (t) =>
          t.organization_id === params[0] &&
          t.source_ip === params[1] &&
          t.threat_type === params[2] &&
          t.status === 'ACTIVE'
      );
      return { rows };
    }
    if (upper.startsWith('UPDATE THREAT_ALERTS SET EVENT_COUNT')) {
      const t = this.tables.threat_alerts.find((x) => x.id === params[2]);
      if (t) {
        t.event_count += Number(params[0]);
        t.last_seen_at = this._now();
        t.description = params[1];
      }
      return { rows: t ? [t] : [] };
    }
    if (upper.startsWith("UPDATE THREAT_ALERTS SET STATUS = 'CONTAINED'")) {
      const t = this.tables.threat_alerts.find((x) => x.id === params[0]);
      if (t) t.status = 'CONTAINED';
      return { rows: [] };
    }
    if (upper.startsWith('INSERT INTO THREAT_ALERTS')) {
      const alert = {
        id: crypto.randomUUID(),
        organization_id: params[0],
        threat_type: params[1],
        detection_method: params[2],
        severity: params[3],
        confidence_score: Number(params[4]),
        source_ip: params[5],
        country_code: params[6],
        targeted_endpoint: params[7],
        event_count: Number(params[8]),
        status: 'ACTIVE',
        description: params[9],
        raw_events: this._parseJsonSafe(params[10], []),
        first_seen_at: this._now(),
        last_seen_at: this._now()
      };
      this.tables.threat_alerts.unshift(alert);
      return { rows: [alert] };
    }
    if (upper.includes('FROM THREAT_ALERTS WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.threat_alerts.filter((t) => t.organization_id === params[0]) };
    }

    if (upper.includes("FROM PREVENTION_ACTIONS WHERE ORGANIZATION_ID = $1 AND TARGET_IDENTIFIER = $2")) {
      return {
        rows: this.tables.prevention_actions.filter(
          (a) =>
            a.organization_id === params[0] &&
            a.target_identifier === params[1] &&
            ['PENDING_APPROVAL', 'EXECUTED'].includes(a.status)
        )
      };
    }
    if (upper.startsWith('INSERT INTO PREVENTION_ACTIONS')) {
      const isAutoProposal = upper.includes("'BLOCK_IP_WAF'");
      let act;
      if (isAutoProposal) {
        act = {
          id: crypto.randomUUID(),
          organization_id: params[0],
          threat_alert_id: params[1],
          action_type: 'BLOCK_IP_WAF',
          target_identifier: params[2],
          enforcement_layer: 'AWS_WAF_AND_PLATFORM_BLOCKLIST',
          requires_approval: true,
          status: 'PENDING_APPROVAL',
          reason: params[3],
          requested_by: params[4],
          approved_by: null,
          rollback_metadata: {},
          created_at: this._now()
        };
      } else {
        act = {
          id: crypto.randomUUID(),
          organization_id: params[0],
          threat_alert_id: null,
          action_type: params[1],
          target_identifier: params[2],
          enforcement_layer: 'AWS_WAF_AND_PLATFORM_BLOCKLIST',
          requires_approval: params[3],
          status: params[4],
          reason: params[5],
          requested_by: params[6],
          approved_by: params[7],
          executed_at: params[8],
          expires_at: params[9],
          rollback_metadata: this._parseJsonSafe(params[10], {}),
          created_at: this._now()
        };
      }
      this.tables.prevention_actions.unshift(act);
      return { rows: [act] };
    }
    if (upper.includes('FROM PREVENTION_ACTIONS WHERE ID = $1 AND ORGANIZATION_ID = $2')) {
      return {
        rows: this.tables.prevention_actions.filter((a) => a.id === params[0] && a.organization_id === params[1])
      };
    }
    if (upper.startsWith("UPDATE PREVENTION_ACTIONS SET STATUS = 'EXECUTED'")) {
      const a = this.tables.prevention_actions.find((x) => x.id === params[3]);
      if (a) {
        a.status = 'EXECUTED';
        a.approved_by = params[0];
        a.executed_at = this._now();
        a.expires_at = params[1];
        a.rollback_metadata = this._parseJsonSafe(params[2], {});
      }
      return { rows: a ? [a] : [] };
    }
    if (upper.startsWith("UPDATE PREVENTION_ACTIONS SET STATUS = 'ROLLED_BACK'")) {
      const a = this.tables.prevention_actions.find((x) => x.id === params[0]);
      if (a) {
        a.status = 'ROLLED_BACK';
        a.rolled_back_at = this._now();
      }
      return { rows: a ? [a] : [] };
    }
    if (upper.includes("FROM PREVENTION_ACTIONS WHERE ORGANIZATION_ID = $1 AND STATUS = 'PENDING_APPROVAL'")) {
      return {
        rows: this.tables.prevention_actions.filter(
          (a) => a.organization_id === params[0] && a.status === 'PENDING_APPROVAL'
        )
      };
    }
    if (upper.includes('FROM PREVENTION_ACTIONS WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.prevention_actions.filter((a) => a.organization_id === params[0]) };
    }

    // 14. AI Security Logs
    if (upper.startsWith('INSERT INTO AI_SECURITY_LOGS')) {
      const log = {
        id: crypto.randomUUID(),
        organization_id: params[0],
        application_name: params[1],
        inspection_stage: params[2],
        verdict: params[3],
        risk_score: Number(params[4]),
        owasp_llm_categories: this._parseJsonSafe(params[5], []),
        detected_violations: this._parseJsonSafe(params[6], []),
        sanitized_prompt: params[7],
        sanitized_response: params[8],
        latency_ms: Number(params[9]),
        source_ip: params[10],
        created_at: this._now()
      };
      this.tables.ai_security_logs.unshift(log);
      return { rows: [log] };
    }
    if (upper.includes('FROM AI_SECURITY_LOGS WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.ai_security_logs.filter((l) => l.organization_id === params[0]) };
    }

    // 15. Compliance Controls
    if (upper.startsWith('INSERT INTO COMPLIANCE_CONTROLS')) {
      if (this.tables.compliance_controls.length === 0) {
        const orgId = '11111111-1111-1111-1111-111111111111';
        const defaultControls = [
          ['ISO_27001', 'A.5.15', 'Organizational Controls', 'Access Control Policy & Enforcement', 'Rules to control physical and logical access to information and other associated assets.', ['IAM', 'AUTH', 'RBAC']],
          ['ISO_27001', 'A.8.2', 'Technological Controls', 'Privileged Access Rights', 'The allocation and use of privileged access rights shall be restricted and managed.', ['IAM', 'PRIVILEGED_ACCESS']],
          ['ISO_27001', 'A.8.5', 'Technological Controls', 'Secure Authentication', 'Secure authentication technologies and procedures shall be implemented based on access restrictions.', ['MFA', 'AUTH', 'BRUTE_FORCE']],
          ['ISO_27001', 'A.8.8', 'Technological Controls', 'Management of Technical Vulnerabilities', 'Information about technical vulnerabilities of information systems in use shall be obtained and evaluated.', ['WEB_SCAN', 'DEPENDENCY_CVE', 'API_SECURITY']],
          ['ISO_27001', 'A.8.15', 'Technological Controls', 'Logging and Audit Trails', 'Logs that record activities, exceptions, faults and other relevant Security events shall be produced and stored.', ['LOGGING', 'AUDIT', 'CLOUDTRAIL']],
          ['ISO_27001', 'A.8.16', 'Technological Controls', 'Monitoring Activities', 'Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken.', ['THREAT_MONITORING', 'AI_SECURITY']],
          ['ISO_27001', 'A.8.20', 'Technological Controls', 'Networks Security', 'Networks and network devices shall be secured, managed and controlled to protect information in systems.', ['NETWORK', 'PORT_SCAN', 'FIREWALL']],
          ['ISO_27001', 'A.8.24', 'Technological Controls', 'Use of Cryptography', 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.', ['ENCRYPTION', 'SSL_TLS', 'STORAGE']],
          ['SOC_2', 'CC6.1', 'Logical and Physical Access Controls', 'Logical Access Security Software and Infrastructure', 'The entity implements logical access security software, infrastructure, and architectures over protected information assets.', ['IAM', 'STORAGE', 'ENCRYPTION', 'AUTH']],
          ['SOC_2', 'CC6.2', 'Logical and Physical Access Controls', 'User Registration and Credential Authorization', 'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.', ['MFA', 'RBAC', 'IAM']],
          ['SOC_2', 'CC6.6', 'Logical and Physical Access Controls', 'Boundary Protection and Network Segmentation', 'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.', ['NETWORK', 'PORT_SCAN', 'HTTP_HEADERS', 'FIREWALL']],
          ['SOC_2', 'CC6.7', 'Logical and Physical Access Controls', 'Data Transmission Encryption', 'The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.', ['SSL_TLS', 'HTTP_HEADERS']],
          ['SOC_2', 'CC7.1', 'System Operations', 'Vulnerability and Configuration Management', 'To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in new vulnerabilities.', ['WEB_SCAN', 'DEPENDENCY_CVE', 'CLOUD_CSPM']],
          ['SOC_2', 'CC7.2', 'System Operations', 'Security Event Monitoring and Anomaly Analysis', 'The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts.', ['THREAT_MONITORING', 'LOGGING', 'AI_SECURITY']],
          ['SOC_2', 'CC7.3', 'System Operations', 'Incident Evaluation and Automated Containment', 'The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives.', ['INCIDENT_RESPONSE', 'FIREWALL']]
        ];
        for (const [fw, code, cat, title, desc, mapped] of defaultControls) {
          this.tables.compliance_controls.push({
            id: crypto.randomUUID(),
            organization_id: orgId,
            framework: fw,
            control_code: code,
            category: cat,
            title,
            description: desc,
            evaluation_type: 'AUTOMATED',
            mapped_rule_categories: mapped,
            status: 'PASSING',
            failing_assets_count: 0,
            evidence_notes: `Automated continuous verification mapped to ${mapped.join(', ')}.`,
            evidence_artifacts: [],
            last_evaluated_at: this._now()
          });
        }
      }
      return { rows: [] };
    }
    if (upper.startsWith('UPDATE COMPLIANCE_CONTROLS SET STATUS = $1, FAILING_ASSETS_COUNT = $2')) {
      const c = this.tables.compliance_controls.find((x) => x.id === params[2]);
      if (c) {
        c.status = params[0];
        c.failing_assets_count = params[1];
        c.last_evaluated_at = this._now();
      }
      return { rows: [] };
    }
    if (upper.startsWith('UPDATE COMPLIANCE_CONTROLS SET EVIDENCE_NOTES = $1')) {
      const c = this.tables.compliance_controls.find((x) => x.id === params[3]);
      if (c) {
        c.evidence_notes = params[0];
        c.status = params[1];
        c.evidence_artifacts = this._parseJsonSafe(params[2], []);
        c.last_evaluated_at = this._now();
      }
      return { rows: c ? [c] : [] };
    }
    if (upper.includes('FROM COMPLIANCE_CONTROLS WHERE ID = $1 AND ORGANIZATION_ID = $2')) {
      return {
        rows: this.tables.compliance_controls.filter((c) => c.id === params[0] && c.organization_id === params[1])
      };
    }
    if (upper.includes('FROM COMPLIANCE_CONTROLS WHERE ORGANIZATION_ID = $1')) {
      return { rows: this.tables.compliance_controls.filter((c) => c.organization_id === params[0]) };
    }

    return { rows: [] };
  }
}

module.exports = {
  EmbeddedPostgresEngine
};
