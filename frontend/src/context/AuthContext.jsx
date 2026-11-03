import React, { createContext, useContext, useState, useEffect } from 'react';
import apiClient from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const saved = sessionStorage.getItem('aegis_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = sessionStorage.getItem('aegis_access_token');
    if (!token) {
      setLoading(false);
      return;
    }
    apiClient
      .get('/auth/me')
      .then((res) => {
        setUser(res.data);
        sessionStorage.setItem('aegis_user', JSON.stringify(res.data));
      })
      .catch(() => {
        sessionStorage.removeItem('aegis_access_token');
        sessionStorage.removeItem('aegis_user');
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = async (email, password) => {
    const res = await apiClient.post('/auth/login', { email, password });
    sessionStorage.setItem('aegis_access_token', res.data.accessToken);
    sessionStorage.setItem('aegis_user', JSON.stringify(res.data.user));
    setUser(res.data.user);
    return res.data.user;
  };

  const register = async (fullName, email, password, role = 'ANALYST') => {
    const res = await apiClient.post('/auth/register', { fullName, email, password, role });
    sessionStorage.setItem('aegis_access_token', res.data.accessToken);
    sessionStorage.setItem('aegis_user', JSON.stringify(res.data.user));
    setUser(res.data.user);
    return res.data.user;
  };

  const logout = async () => {
    try {
      await apiClient.post('/auth/logout');
    } catch {
      // Ignore network errors on logout
    }
    sessionStorage.removeItem('aegis_access_token');
    sessionStorage.removeItem('aegis_user');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
