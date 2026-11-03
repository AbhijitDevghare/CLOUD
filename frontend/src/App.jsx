import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import CloudSecurityPage from './pages/CloudSecurityPage';
import VulnerabilityPage from './pages/VulnerabilityPage';
import ThreatPreventionPage from './pages/ThreatPreventionPage';
import AiSecurityPage from './pages/AiSecurityPage';
import CompliancePage from './pages/CompliancePage';
import AdminAuditPage from './pages/AdminAuditPage';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400 text-sm">
        Initializing AegisCloud Security Platform...
      </div>
    );
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="cloud" element={<CloudSecurityPage />} />
            <Route path="vulnerabilities" element={<VulnerabilityPage />} />
            <Route path="threats" element={<ThreatPreventionPage />} />
            <Route path="ai-security" element={<AiSecurityPage />} />
            <Route path="compliance" element={<CompliancePage />} />
            <Route path="admin" element={<AdminAuditPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
