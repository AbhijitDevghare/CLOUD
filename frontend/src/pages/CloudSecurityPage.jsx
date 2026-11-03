import React, { useEffect, useState } from 'react';
import { Cloud, Plus, Play, Trash2, ShieldCheck, AlertTriangle, Lock, Globe } from 'lucide-react';
import apiClient from '../api/client';
import { useAuth } from '../context/AuthContext';

export default function CloudSecurityPage() {
  const { user } = useAuth();
  const [accounts, setAccounts] = useState([]);
  const [resources, setResources] = useState([]);
  const [scanningId, setScanningId] = useState(null);
  const [message, setMessage] = useState(null);

  // Onboarding Form State
  const [provider, setProvider] = useState('AWS');
  const [accountName, setAccountName] = useState('AWS Production Core Infrastructure');
  const [accountIdentifier, setAccountIdentifier] = useState('445566778899');
  const [authMethod, setAuthMethod] = useState('IAM_ASSUME_ROLE');
  const [roleArnOrKey, setRoleArnOrKey] = useState('arn:aws:iam::445566778899:role/AegisSecurityAuditRole');
  const [externalIdOrSecret, setExternalIdOrSecret] = useState('aegis-ext-id-998877');
  const [connectionMode, setConnectionMode] = useState('DEMO_SIMULATION');

  const fetchCloudData = async () => {
    try {
      const [accRes, resRes] = await Promise.all([
        apiClient.get('/cloud/accounts'),
        apiClient.get('/cloud/resources')
      ]);
      setAccounts(accRes.data.accounts || []);
      setResources(resRes.data.resources || []);
    } catch (err) {
      console.error('Error loading cloud data:', err);
    }
  };

  useEffect(() => {
    fetchCloudData();
  }, []);

  const handleProviderChange = (newProv) => {
    setProvider(newProv);
    if (newProv === 'AWS') {
      setAccountName('AWS Production Core Infrastructure');
      setAccountIdentifier('445566778899');
      setAuthMethod('IAM_ASSUME_ROLE');
      setRoleArnOrKey('arn:aws:iam::445566778899:role/AegisSecurityAuditRole');
    } else if (newProv === 'AZURE') {
      setAccountName('Azure Enterprise Cloud Hub');
      setAccountIdentifier('sub-9a8b7c6d-5e4f-3a2b-1c0d');
      setAuthMethod('SERVICE_PRINCIPAL');
      setRoleArnOrKey('app-sp-azure-sec-reader');
    } else {
      setAccountName('GCP AI & Data Platform Project');
      setAccountIdentifier('gcp-prod-ai-394810');
      setAuthMethod('SERVICE_ACCOUNT');
      setRoleArnOrKey('aegis-scanner@gcp-prod-ai-394810.iam.gserviceaccount.com');
    }
  };

  const handleConnectAccount = async (e) => {
    e.preventDefault();
    setMessage(null);
    try {
      await apiClient.post('/cloud/accounts', {
        provider,
        accountName,
        accountIdentifier,
        authMethod,
        credentials: {
          principal: roleArnOrKey,
          secretOrExternalId: externalIdOrSecret
        },
        regions: ['us-east-1', 'eu-west-1'],
        connectionMode
      });
      setMessage({ type: 'success', text: `${provider} account connected and credentials encrypted with AES-256-GCM.` });
      await fetchCloudData();
    } catch (err) {
      setMessage({
        type: 'error',
        text: err.response?.data?.message || 'Failed to connect cloud account.'
      });
    }
  };

  const handleRunScan = async (accountId) => {
    setScanningId(accountId);
    setMessage(null);
    try {
      const res = await apiClient.post(`/cloud/accounts/${accountId}/scan`);
      setMessage({
        type: 'success',
        text: `CSPM Scan completed (${res.data.mode}): Discovered ${res.data.resourcesDiscovered} resources and identified ${res.data.findingsDetected} misconfiguration findings.`
      });
      await fetchCloudData();
    } catch (err) {
      setMessage({
        type: 'error',
        text: err.response?.data?.message || 'Cloud posture scan failed.'
      });
    } finally {
      setScanningId(null);
    }
  };

  const handleDeleteAccount = async (accountId) => {
    try {
      await apiClient.delete(`/cloud/accounts/${accountId}`);
      await fetchCloudData();
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.message || 'Could not remove account.' });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Multi-Cloud Security Posture Management (CSPM)</h2>
        <p className="text-sm text-slate-400">
          Connect AWS, Microsoft Azure, and Google Cloud Platform accounts to inventory resources and detect storage, IAM, network, and encryption misconfigurations
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
          <button onClick={() => setMessage(null)} className="text-slate-400 hover:text-white">
            ✕
          </button>
        </div>
      )}

      {/* Connect Cloud Account Form (Admin Only) */}
      {user?.role === 'ADMIN' && (
        <form onSubmit={handleConnectAccount} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-white text-sm flex items-center gap-2">
              <Plus className="w-4 h-4 text-cyan-400" />
              Onboard Cloud Account (AES-256-GCM Credential Envelope Encryption)
            </h3>
            <span className="text-[11px] text-slate-400 flex items-center gap-1">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              Least-Privilege Read-Only IAM Recommended
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Cloud Provider</label>
              <select
                value={provider}
                onChange={(e) => handleProviderChange(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white"
              >
                <option value="AWS">Amazon Web Services (AWS)</option>
                <option value="AZURE">Microsoft Azure</option>
                <option value="GCP">Google Cloud Platform (GCP)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Account / Project Alias</label>
              <input
                type="text"
                required
                value={accountName}
                onChange={(e) => setAccountName(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Account / Subscription ID</label>
              <input
                type="text"
                required
                value={accountIdentifier}
                onChange={(e) => setAccountIdentifier(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Role ARN / Service Principal</label>
              <input
                type="text"
                required
                value={roleArnOrKey}
                onChange={(e) => setRoleArnOrKey(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">External ID / Client Secret</label>
              <input
                type="password"
                required
                value={externalIdOrSecret}
                onChange={(e) => setExternalIdOrSecret(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Execution Mode</label>
              <select
                value={connectionMode}
                onChange={(e) => setConnectionMode(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white"
              >
                <option value="DEMO_SIMULATION">Sandbox Posture Evaluation</option>
                <option value="LIVE">Live Cloud SDK API</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition"
            >
              Connect & Encrypt Cloud Account
            </button>
          </div>
        </form>
      )}

      {/* Connected Accounts List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="font-semibold text-white text-sm">Connected Cloud Environments ({accounts.length})</h3>
        {accounts.length === 0 ? (
          <div className="p-6 text-center bg-slate-950/60 rounded-lg border border-slate-800 text-xs text-slate-400">
            No cloud accounts connected yet. Connect an AWS, Azure, or GCP account above to run a posture assessment.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {accounts.map((acc) => (
              <div
                key={acc.id}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between gap-4"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold px-2.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                      {acc.provider}
                    </span>
                    <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {acc.connection_mode}
                    </span>
                  </div>
                  <h4 className="font-semibold text-white text-sm">{acc.account_name}</h4>
                  <p className="text-xs text-slate-400 font-mono">ID: {acc.account_identifier}</p>
                  <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800/80">
                    <span className="text-slate-400">Assets: {acc.resource_count || 0}</span>
                    <span className="font-bold text-emerald-400">Posture Score: {acc.security_score}/100</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleRunScan(acc.id)}
                    disabled={scanningId === acc.id}
                    className="flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 text-xs font-semibold transition"
                  >
                    <Play className="w-3.5 h-3.5" />
                    {scanningId === acc.id ? 'Scanning Posture...' : 'Run CSPM Audit Scan'}
                  </button>
                  {user?.role === 'ADMIN' && (
                    <button
                      onClick={() => handleDeleteAccount(acc.id)}
                      className="p-2 rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-300"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Discovered Cloud Resources Inventory */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="font-semibold text-white text-sm">Discovered Multi-Cloud Resource Inventory ({resources.length})</h3>
        {resources.length === 0 ? (
          <div className="p-6 text-center bg-slate-950/60 rounded-lg border border-slate-800 text-xs text-slate-400">
            Click &quot;Run CSPM Audit Scan&quot; on any connected cloud account above to discover cloud assets and evaluate misconfigurations.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Provider</th>
                  <th className="py-2.5 px-3">Service</th>
                  <th className="py-2.5 px-3">Resource Name & Identifier</th>
                  <th className="py-2.5 px-3">Region</th>
                  <th className="py-2.5 px-3">Exposure</th>
                  <th className="py-2.5 px-3">Encryption</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {resources.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 font-semibold text-cyan-300">{r.provider}</td>
                    <td className="py-2.5 px-3 text-slate-300">{r.service_type}</td>
                    <td className="py-2.5 px-3">
                      <p className="font-medium text-white">{r.resource_name}</p>
                      <p className="text-[11px] text-slate-500 font-mono truncate max-w-md">{r.resource_id}</p>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">{r.region}</td>
                    <td className="py-2.5 px-3">
                      {r.is_public ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          <Globe className="w-3 h-3" /> Public Exposed
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300">
                          <ShieldCheck className="w-3 h-3" /> Private
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      {r.encryption_enabled ? (
                        <span className="text-emerald-400">Encrypted</span>
                      ) : (
                        <span className="text-rose-400 font-semibold flex items-center gap-1">
                          <AlertTriangle className="w-3.5 h-3.5" /> Unencrypted
                        </span>
                      )}
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
