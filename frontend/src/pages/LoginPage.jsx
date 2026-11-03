import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, User, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function LoginPage() {
  const { login, register } = useAuth();
  const navigate = useNavigate();

  const [isRegisterMode, setIsRegisterMode] = useState(false);
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('admin@aegiscloud.io');
  const [password, setPassword] = useState('Admin@12345!');
  const [role, setRole] = useState('ANALYST');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      if (isRegisterMode) {
        await register(fullName, email, password, role);
      } else {
        await login(email, password);
      }
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setSubmitting(false);
    }
  };

  const fillRolePreset = (presetEmail, presetPass) => {
    setIsRegisterMode(false);
    setEmail(presetEmail);
    setPassword(presetPass);
    setError('');
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
      <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-6">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400">
            <Shield className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">AegisCloud Security Platform</h1>
            <p className="text-xs text-slate-400">Unified Cloud, Web, API & AI Security Command Center</p>
          </div>
        </div>

        {/* Quick RBAC Role Preset Selector */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 space-y-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Quick RBAC Role Presets (Seeded Enterprise Accounts)
          </p>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => fillRolePreset('admin@aegiscloud.io', 'Admin@12345!')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 transition"
            >
              Platform Admin
            </button>
            <button
              type="button"
              onClick={() => fillRolePreset('analyst@aegiscloud.io', 'Analyst@12345!')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 transition"
            >
              SOC Analyst
            </button>
            <button
              type="button"
              onClick={() => fillRolePreset('auditor@aegiscloud.io', 'Auditor@12345!')}
              className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 transition"
            >
              GRC Auditor
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-500/40 flex items-center gap-2.5 text-xs text-rose-200">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegisterMode && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alex Rivera"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Enterprise Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {isRegisterMode && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">RBAC Role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="ANALYST">Security Analyst (SOC & AppSec)</option>
                <option value="AUDITOR">Compliance & GRC Auditor</option>
                <option value="ADMIN">Platform Administrator</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-2.5 px-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm rounded-lg transition disabled:opacity-50"
          >
            {submitting
              ? 'Authenticating...'
              : isRegisterMode
              ? 'Create Account & Issue JWT'
              : 'Sign In to Security Command Center'}
          </button>
        </form>

        <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span className="flex items-center gap-1 text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" />
            JWT + RBAC + Audit Active
          </span>
          <button
            type="button"
            onClick={() => setIsRegisterMode(!isRegisterMode)}
            className="text-cyan-400 hover:underline font-medium"
          >
            {isRegisterMode ? 'Back to Sign In' : 'Register New Analyst'}
          </button>
        </div>
      </div>
    </div>
  );
}
