import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Cloud,
  AlertTriangle,
  Activity,
  Ban,
  CheckCircle2,
  Sparkles,
  RefreshCw,
  ArrowRight,
  Server
} from 'lucide-react';
import apiClient from '../api/client';

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchOverview = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get('/dashboard/overview');
      setData(res.data);
    } catch (err) {
      console.error('Failed to load dashboard overview:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverview();
  }, []);

  if (loading || !data) {
    return (
      <div className="p-8 text-center text-slate-400 text-sm">
        Loading Unified Security Command Center metrics...
      </div>
    );
  }

  const {
    kpis,
    severityDistribution,
    cloudByProvider,
    complianceReadiness,
    topPriorityFindings,
    recentThreats,
    pendingPreventionApprovals,
    systemHealth
  } = data;

  const scoreColor =
    kpis.overallSecurityScore >= 80
      ? 'text-emerald-400'
      : kpis.overallSecurityScore >= 55
      ? 'text-amber-400'
      : 'text-rose-400';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Unified Security Command Center</h2>
          <p className="text-sm text-slate-400">
            Real-time posture across Multi-Cloud (AWS, Azure, GCP), Websites, REST APIs, and AI/LLM Applications
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            DB: {systemHealth.databaseMode} | Python Engine: {systemHealth.pythonServiceOnline ? 'ONLINE' : 'NATIVE_STANDBY'}
          </span>
          <button
            onClick={fetchOverview}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-white border border-slate-700 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Tier 1: KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Global Security Score</span>
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <div className={`text-3xl font-extrabold ${scoreColor}`}>
            {kpis.overallSecurityScore}
            <span className="text-sm font-normal text-slate-500"> / 100</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Composite Cloud, AppSec & Threat Index
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Cloud & Web Assets</span>
            <Cloud className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-3xl font-bold text-white">
            {kpis.totalCloudResources + kpis.monitoredWebAndApiTargets}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {kpis.connectedCloudAccounts} Cloud Accts • {kpis.totalCloudResources} Cloud Assets • {kpis.monitoredWebAndApiTargets} Web/APIs
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Critical & High Findings</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-3xl font-bold text-rose-400">
            {kpis.criticalFindingsCount + kpis.highFindingsCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {kpis.criticalFindingsCount} Critical • {kpis.highFindingsCount} High ({kpis.openVulnerabilitiesCount} total open)
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Active Threats & Approvals</span>
            <Activity className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-3xl font-bold text-amber-400">
            {kpis.activeThreatsCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {kpis.pendingApprovalsCount} Pending Admin Prevention Approvals
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Blocked IPs & AI Guard</span>
            <Ban className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold text-emerald-400">
            {kpis.blockedIpsCount + kpis.aiBlockedPromptsCount}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            {kpis.blockedIpsCount} WAF Blocked IPs • {kpis.aiBlockedPromptsCount} AI Prompt Violations Stopped
          </p>
        </div>
      </div>

      {/* Tier 2: Priority Findings & Live Threat Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Priority Vulnerabilities */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <h3 className="font-semibold text-white text-sm">Top AI-Prioritized Security Findings</h3>
              </div>
              <Link to="/vulnerabilities" className="text-xs text-cyan-400 hover:underline flex items-center gap-1">
                Explore All <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            {topPriorityFindings.length === 0 ? (
              <div className="p-6 text-center bg-slate-950/60 rounded-lg border border-slate-800 text-xs text-slate-400">
                No open vulnerabilities detected yet. Connect a Cloud Account or run a Website/Dependency Scan to populate findings.
              </div>
            ) : (
              <div className="space-y-2.5">
                {topPriorityFindings.map((f) => (
                  <div
                    key={f.id}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 flex items-start justify-between gap-3"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                            f.severity === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : f.severity === 'HIGH'
                              ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                              : 'bg-amber-500/20 text-amber-300'
                          }`}
                        >
                          {f.severity} • CVSS {f.cvss_score}
                        </span>
                        <span className="text-xs font-medium text-white truncate">{f.title}</span>
                      </div>
                      <p className="text-xs text-slate-400 truncate">Asset: {f.affected_asset}</p>
                    </div>
                    <Link
                      to="/ai-security"
                      className="shrink-0 px-2.5 py-1 rounded bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25 text-xs font-medium"
                    >
                      AI Playbook
                    </Link>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Live Threats & Pending Approvals */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-400" />
              <h3 className="font-semibold text-white text-sm">Active Threat Feed & Containment Queue</h3>
            </div>
            <Link to="/threats" className="text-xs text-cyan-400 hover:underline flex items-center gap-1">
              Manage Prevention <ArrowRight className="w-3 h-3" />
            </Link>
          </div>

          {pendingPreventionApprovals.length > 0 && (
            <div className="mb-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-between">
              <div className="text-xs text-amber-200">
                <span className="font-bold">{pendingPreventionApprovals.length} Prevention Action(s)</span> awaiting Administrator approval (e.g. WAF Block for {pendingPreventionApprovals[0].target_identifier}).
              </div>
              <Link
                to="/threats"
                className="px-2.5 py-1 rounded bg-amber-500 text-slate-950 font-semibold text-xs hover:bg-amber-400"
              >
                Review & Approve
              </Link>
            </div>
          )}

          {recentThreats.length === 0 ? (
            <div className="p-6 text-center bg-slate-950/60 rounded-lg border border-slate-800 text-xs text-slate-400">
              No active threat alerts recorded. Use the Threat & Prevention simulator or ingest telemetry to test real-time detection.
            </div>
          ) : (
            <div className="space-y-2.5">
              {recentThreats.slice(0, 4).map((t) => (
                <div
                  key={t.id}
                  className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                        {t.severity}
                      </span>
                      <span className="text-xs font-semibold text-white">{t.threat_type}</span>
                      <span className="text-[11px] text-slate-400">({t.event_count} events)</span>
                    </div>
                    <p className="text-xs text-slate-400 truncate">
                      Source IP: <span className="text-slate-200 font-mono">{t.source_ip}</span> ({t.country_code}) → {t.targeted_endpoint}
                    </p>
                  </div>
                  <span
                    className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                      t.status === 'CONTAINED'
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : 'bg-rose-500/20 text-rose-300'
                    }`}
                  >
                    {t.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Tier 3: Severity Breakdown, Multi-Cloud Status & Compliance Readiness */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Vulnerability Severity Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <h3 className="font-semibold text-white text-sm">Vulnerability Distribution</h3>
          {[
            { label: 'Critical', count: severityDistribution.CRITICAL, color: 'bg-rose-500' },
            { label: 'High', count: severityDistribution.HIGH, color: 'bg-orange-500' },
            { label: 'Medium', count: severityDistribution.MEDIUM, color: 'bg-amber-500' },
            { label: 'Low', count: severityDistribution.LOW, color: 'bg-sky-500' },
            { label: 'Info', count: severityDistribution.INFO, color: 'bg-slate-500' }
          ].map((item) => (
            <div key={item.label} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300">{item.label}</span>
                <span className="font-semibold text-white">{item.count}</span>
              </div>
              <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full ${item.color}`}
                  style={{ width: `${Math.min(100, item.count * 15)}%` }}
                />
              </div>
            </div>
          ))}
        </div>

        {/* Multi-Cloud Environment Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm">Multi-Cloud Security Posture</h3>
            <Link to="/cloud" className="text-xs text-cyan-400 hover:underline">
              Connect Cloud
            </Link>
          </div>
          <div className="space-y-2.5">
            {cloudByProvider.map((c) => (
              <div key={c.provider} className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between">
                <div>
                  <p className="text-xs font-bold text-white">{c.provider} Environment</p>
                  <p className="text-[11px] text-slate-400">
                    {c.connectedAccounts} Account(s) • {c.totalResources} Discovered Assets
                  </p>
                </div>
                <span className="text-xs font-medium px-2.5 py-1 rounded bg-slate-800 text-cyan-300">
                  {c.publicResources} Public Exposed
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Compliance Readiness */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm">Continuous Compliance Readiness</h3>
            <Link to="/compliance" className="text-xs text-cyan-400 hover:underline">
              Audit Checklist
            </Link>
          </div>

          <div className="space-y-3">
            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-white flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ISO/IEC 27001:2022
                </span>
                <span className="font-bold text-emerald-400">{complianceReadiness.ISO_27001}% Passing</span>
              </div>
              <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500 transition-all"
                  style={{ width: `${complianceReadiness.ISO_27001}%` }}
                />
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-white flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                  SOC 2 (Trust Services Criteria)
                </span>
                <span className="font-bold text-cyan-400">{complianceReadiness.SOC_2}% Passing</span>
              </div>
              <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-cyan-500 transition-all"
                  style={{ width: `${complianceReadiness.SOC_2}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
