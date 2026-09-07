import { createContext, useContext, useState, useCallback } from 'react';
import client from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem('cs_user');
    return raw ? JSON.parse(raw) : null;
  });
  // Expose token so RealTimeContext can gate WebSocket connection
  const token = localStorage.getItem('cs_token');

  const login = useCallback(async (email, password) => {
    const { data } = await client.post('/auth/login', { email, password });
    localStorage.setItem('cs_token', data.token);
    localStorage.setItem('cs_user', JSON.stringify(data.user));
    setUser(data.user);
    return data.user;
  }, []);

  const loginMFA = useCallback(async (email, code) => {
    const { data } = await client.post('/auth/verify-mfa', { email, code });
    localStorage.setItem('cs_token', data.token);
    localStorage.setItem('cs_user', JSON.stringify(data.user));
    setUser(data.user);
    return data.user;
  }, []);

  const register = useCallback(async (name, email, password, phone) => {
    const { data } = await client.post('/auth/register', { name, email, password, phone });
    localStorage.setItem('cs_token', data.token);
    localStorage.setItem('cs_user', JSON.stringify(data.user));
    setUser(data.user);
    return data.user;
  }, []);

  const updateProfile = useCallback(async (profileData) => {
    const { data } = await client.put('/auth/profile', profileData);
    if (data.token) {
      localStorage.setItem('cs_token', data.token);
    }
    localStorage.setItem('cs_user', JSON.stringify(data.user));
    setUser(data.user);
    return data.user;
  }, []);

  const verifyCode = useCallback(async (type, code) => {
    const { data } = await client.post('/auth/verify-code', { type, code });
    localStorage.setItem('cs_user', JSON.stringify(data.user));
    setUser(data.user);
    return data.user;
  }, []);

  const forgotPassword = useCallback(async (payload) => {
    const { data } = await client.post('/auth/forgot-password', payload);
    return data;
  }, []);

  const resetPassword = useCallback(async (payload) => {
    const { data } = await client.post('/auth/reset-password', payload);
    return data;
  }, []);

  const logout = useCallback(async () => {
    try {
      await client.post('/auth/logout');
    } catch (e) {
      console.warn('Logout log error', e);
    }
    localStorage.removeItem('cs_token');
    localStorage.removeItem('cs_user');
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ 
      user, 
      token, 
      login, 
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
