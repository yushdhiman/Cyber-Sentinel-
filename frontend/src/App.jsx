import { useEffect, useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { RealTimeProvider } from './context/RealTimeContext';
import ProtectedRoute from './components/ProtectedRoute';
import Layout from './components/Layout';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import LogAnalyzer from './pages/LogAnalyzer';
import VulnScanner from './pages/VulnScanner';
import ThreatIntel from './pages/ThreatIntel';
import Assistant from './pages/Assistant';
import SecurityTools from './pages/SecurityTools';
import ProtectionCenter from './pages/ProtectionCenter';
import Sandbox from './pages/Sandbox';
import Profile from './pages/Profile';

function AppShell() {
  const [theme, setTheme] = useState(() => localStorage.getItem('cs_theme') || 'dark');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('cs_theme', theme);
  }, [theme]);

  function toggleTheme() {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'));
  }

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <Layout theme={theme} onToggleTheme={toggleTheme}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/log-analyzer" element={<LogAnalyzer />} />
                <Route path="/vuln-scanner" element={<VulnScanner />} />
                <Route path="/threat-intel" element={<ThreatIntel />} />
                <Route path="/assistant" element={<Assistant />} />
                <Route path="/security-tools" element={<SecurityTools />} />
                <Route path="/protection-center" element={<ProtectionCenter />} />
                <Route path="/sandbox" element={<Sandbox />} />
                <Route path="/profile" element={<Profile />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      {/* RealTimeProvider inside AuthProvider so it can read the token */}
      <RealTimeProvider>
        <AppShell />
      </RealTimeProvider>
    </AuthProvider>
  );
}
