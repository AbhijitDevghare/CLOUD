import React, { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Cloud,
  Bug,
  Activity,
  Sparkles,
  FileCheck2,
  Users,
  LogOut,
  Bell,
  Radio
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { getSocket } from '../api/client';

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [liveToast, setLiveToast] = useState(null);
  const [socketConnected, setSocketConnected] = useState(false);

  useEffect(() => {
    const socket = getSocket();

    const onConnect = () => setSocketConnected(true);
    const onDisconnect = () => setSocketConnected(false);

    const onNewThreat = (payload) => {
      const first = payload?.alerts?.[0];
      if (first) {
        setLiveToast({
          type: 'THREAT',
          title: `Live Threat Alert: ${first.threat_type}`,
          detail: `${first.severity} severity from IP ${first.source_ip} targeting ${first.targeted_endpoint}`
        });
      }
    };

    const onCloudScan = (payload) => {
      setLiveToast({
        type: 'SCAN',
        title: `${payload.provider} Cloud Posture Scan Completed`,
        detail: `${payload.accountName}: ${payload.findingsCount} findings (Score: ${payload.securityScore}/100)`
      });
    };

    const onAiViolation = (payload) => {
      setLiveToast({
        type: 'AI',
        title: `AI Application Guardrail Verdict: ${payload.verdict}`,
        detail: `App: ${payload.application_name} (Risk Score: ${payload.risk_score})`
      });
    };

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('threat:new_alert', onNewThreat);
    socket.on('cloud:scan_completed', onCloudScan);
    socket.on('ai_security:violation_detected', onAiViolation);

    if (socket.connected) setSocketConnected(true);

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('threat:new_alert', onNewThreat);
      socket.off('cloud:scan_completed', onCloudScan);
      socket.off('ai_security:violation_detected', onAiViolation);
    };
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const navItems = [
    { to: '/', label: 'Command Center', icon: LayoutDashboard, end: true },
    { to: '/cloud', label: 'Multi-Cloud CSPM', icon: Cloud },
    { to: '/vulnerabilities', label: 'Vulnerability Scanner', icon: Bug },
    { to: '/threats', label: 'Threat & Prevention', icon: Activity },
    { to: '/ai-security', label: 'AI Security & LLM Guard', icon: Sparkles },
    { to: '/compliance', label: 'ISO 27001 & SOC 2', icon: FileCheck2 },
    { to: '/admin', label: 'RBAC & Audit Logs', icon: Users }
  ];

  const roleBadgeColor =
    user?.role === 'ADMIN'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
      : user?.role === 'ANALYST'
      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
      : 'bg-amber-500/20 text-amber-300 border-amber-500/40';

  return (
    <div className="min-h-screen flex bg-slate-950 text-slate-100">
      {/* Sidebar */}
      <aside className="w-68 bg-slate-900/90 border-r border-slate-800 flex flex-col justify-between shrink-0">
        <div>
          <div className="p-5 border-b border-slate-800 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-cyan-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-bold text-base tracking-tight text-white">AegisCloud AI</h1>
              <p className="text-xs text-slate-400">Unified SecOps Platform</p>
            </div>
          </div>

          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`
                  }
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* User Footer */}
        <div className="p-4 border-t border-slate-800 space-y-3 bg-slate-900/50">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 flex items-center gap-1.5">
              <Radio className={`w-3.5 h-3.5 ${socketConnected ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
              {socketConnected ? 'Socket.IO Live Stream' : 'Telemetry Standby'}
            </span>
            <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${roleBadgeColor}`}>
              {user?.role}
            </span>
          </div>

          <div className="text-xs truncate">
            <p className="font-semibold text-slate-200 truncate">{user?.fullName}</p>
            <p className="text-slate-400 truncate">{user?.email}</p>
          </div>

          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-rose-950/60 hover:text-rose-300 border border-slate-700 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign Out & Revoke Token
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {liveToast && (
          <div className="bg-slate-900 border-b border-cyan-500/40 px-6 py-2.5 flex items-center justify-between">
            <div className="flex items-center gap-3 text-xs">
              <Bell className="w-4 h-4 text-cyan-400 animate-bounce" />
              <span className="font-semibold text-cyan-300">{liveToast.title}:</span>
              <span className="text-slate-300">{liveToast.detail}</span>
            </div>
            <button
              onClick={() => setLiveToast(null)}
              className="text-xs text-slate-400 hover:text-white px-2 py-0.5 rounded bg-slate-800"
            >
              Dismiss
            </button>
          </div>
        )}

        <main className="flex-1 p-6 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
