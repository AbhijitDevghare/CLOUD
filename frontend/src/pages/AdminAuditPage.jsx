import React, { useEffect, useState } from 'react';
import { Users, Shield, ScrollText } from 'lucide-react';
import apiClient from '../api/client';
import { useAuth } from '../context/AuthContext';

export default function AdminAuditPage() {
  const { user } = useAuth();
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [message, setMessage] = useState(null);

  const fetchAdminData = async () => {
    try {
      const logsRes = await apiClient.get('/auth/audit-logs?limit=100');
      setAuditLogs(logsRes.data.auditLogs || []);

      if (['ADMIN', 'AUDITOR'].includes(user?.role)) {
        const usersRes = await apiClient.get('/auth/users');
        setUsers(usersRes.data.users || []);
      }
    } catch (err) {
      console.error('Error loading admin/audit data:', err);
    }
  };

  useEffect(() => {
    fetchAdminData();
  }, [user]);

  const handleRoleUpdate = async (targetId, newRole) => {
    try {
      await apiClient.patch(`/auth/users/${targetId}`, { role: newRole });
      setMessage(`Updated user RBAC role to ${newRole}.`);
      await fetchAdminData();
    } catch (err) {
      setMessage(err.response?.data?.message || 'Role update failed.');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Identity Governance, RBAC & Immutable Audit Trail</h2>
        <p className="text-sm text-slate-400">
          Module 1: Role-Based Access Control (Admin, Security Analyst, GRC Auditor), Login Activity Tracking, and Append-Only Security Audit Logs
        </p>
      </div>

      {message && (
        <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-xs text-cyan-200 flex justify-between">
          <span>{message}</span>
          <button onClick={() => setMessage(null)}>✕</button>
        </div>
      )}

      {/* User Management Table */}
      {['ADMIN', 'AUDITOR'].includes(user?.role) && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="font-semibold text-white text-sm flex items-center gap-2">
            <Users className="w-4 h-4 text-cyan-400" />
            Platform Users & Role-Based Access Control ({users.length})
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Full Name</th>
                  <th className="py-2.5 px-3">Email</th>
                  <th className="py-2.5 px-3">RBAC Role</th>
                  <th className="py-2.5 px-3">MFA Status</th>
                  <th className="py-2.5 px-3">Last Login IP</th>
                  <th className="py-2.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="py-2.5 px-3 font-semibold text-white">{u.full_name}</td>
                    <td className="py-2.5 px-3 text-slate-300 font-mono">{u.email}</td>
                    <td className="py-2.5 px-3">
                      {user?.role === 'ADMIN' ? (
                        <select
                          value={u.role}
                          onChange={(e) => handleRoleUpdate(u.id, e.target.value)}
                          className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs text-white"
                        >
                          <option value="ADMIN">ADMIN</option>
                          <option value="ANALYST">ANALYST</option>
                          <option value="AUDITOR">AUDITOR</option>
                        </select>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold">{u.role}</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      {u.mfa_enabled ? (
                        <span className="text-emerald-400 font-medium">MFA Enforced</span>
                      ) : (
                        <span className="text-slate-400">Standard JWT</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400">{u.last_login_ip || '127.0.0.1'}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-[10px] font-bold">
                        {u.is_active ? 'ACTIVE' : 'DISABLED'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Immutable Audit Trail */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-white text-sm flex items-center gap-2">
            <ScrollText className="w-4 h-4 text-emerald-400" />
            Immutable Platform Security Audit Trail ({auditLogs.length})
          </h3>
          <span className="text-xs text-slate-400 flex items-center gap-1">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            Satisfies ISO 27001 A.8.15 &amp; SOC 2 CC7.2
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Actor &amp; Role</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Resource</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Audit Context</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {auditLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/40">
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                    {new Date(log.created_at).toLocaleString()}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="text-white font-medium">{log.actor_email}</span>
                    <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">
                      {log.actor_role}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono font-semibold text-cyan-300">{log.action}</td>
                  <td className="py-2.5 px-3 text-slate-300">{log.resource_type}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-400">{log.ip_address}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        log.status === 'SUCCESS'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : 'bg-rose-500/20 text-rose-300'
                      }`}
                    >
                      {log.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                    {JSON.stringify(log.details)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
