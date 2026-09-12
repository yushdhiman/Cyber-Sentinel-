import { createContext, useContext, useState, useCallback } from 'react';
import client from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => {
    return localStorage.getItem('cs_token') || null;
  });

  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem('cs_user');
    const savedToken = localStorage.getItem('cs_token');
    if (raw && savedToken) {
      try {
        return JSON.parse(raw);
      } catch (e) {
        return null;
      }
    }
    return null;
  });

  const login = useCallback(async (email, password, mfaCode) => {
    const { data } = await client.post('/auth/login', { email, password, mfaCode });
    if (data.mfaRequired) {
      return data;
    }
    if (data.token && data.user) {
      localStorage.setItem('cs_token', data.token);
      if (data.refreshToken) {
        localStorage.setItem('cs_refresh_token', data.refreshToken);
      }
      localStorage.setItem('cs_user', JSON.stringify(data.user));
      setToken(data.token);
      setUser(data.user);
      return data.user;
    }
    throw new Error(data.error || 'Authentication response missing token');
  }, []);

  const verifyMFA = useCallback(async (mfaTicket, code) => {
    const { data } = await client.post('/auth/verify-mfa', { mfaTicket, code });
    if (data.token && data.user) {
      localStorage.setItem('cs_token', data.token);
      if (data.refreshToken) {
        localStorage.setItem('cs_refresh_token', data.refreshToken);
      }
      localStorage.setItem('cs_user', JSON.stringify(data.user));
      setToken(data.token);
      setUser(data.user);
      return data.user;
    }
    throw new Error(data.error || 'MFA verification failed');
  }, []);

  const loginMFA = verifyMFA;

  const register = useCallback(async (name, email, password, phone) => {
    const { data } = await client.post('/auth/register', { name, email, password, phone });
    if (data.token && data.user) {
      localStorage.setItem('cs_token', data.token);
      if (data.refreshToken) {
        localStorage.setItem('cs_refresh_token', data.refreshToken);
      }
      localStorage.setItem('cs_user', JSON.stringify(data.user));
      setToken(data.token);
      setUser(data.user);
      return data.user;
    }
    throw new Error(data.error || 'Registration response missing token');
  }, []);

  const updateProfile = useCallback(async (profileData) => {
    const { data } = await client.put('/auth/profile', profileData);
    if (data.token) {
      localStorage.setItem('cs_token', data.token);
      setToken(data.token);
    }
    if (data.user) {
      localStorage.setItem('cs_user', JSON.stringify(data.user));
      setUser(data.user);
    }
    return data.user;
  }, []);

  const verifyCode = useCallback(async () => user, [user]);

  const forgotPassword = useCallback(async (payload) => {
    const { data } = await client.post('/auth/forgot-password', payload);
    return data;
  }, []);

  const resetPassword = useCallback(async (payload) => {
    const { data } = await client.post('/auth/reset-password', payload);
    return data;
  }, []);

  const logout = useCallback(async () => {
    const refreshToken = localStorage.getItem('cs_refresh_token');
    try {
      await client.post('/auth/logout', { refreshToken });
    } catch (e) {
      // Ignore network errors on logout
    }
    localStorage.removeItem('cs_token');
    localStorage.removeItem('cs_refresh_token');
    localStorage.removeItem('cs_user');
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ 
      user, 
      token, 
      isAuthenticated: Boolean(token && user),
      login, 
      verifyMFA,
      loginMFA, 
      register, 
      logout, 
      updateProfile, 
      verifyCode,
      forgotPassword,
      resetPassword
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
