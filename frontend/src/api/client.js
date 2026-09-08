import axios from 'axios';

const getBaseUrl = () => {
  if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
  if (typeof window !== 'undefined' && window.location.hostname.includes('vercel.app')) {
    return 'https://cyber-sentinel-7xfn.onrender.com/api';
  }
  return '/api';
};

const client = axios.create({
  baseURL: getBaseUrl(),
  timeout: 12000,
});

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('cs_token') || 'sentinel-direct-token';
  config.headers.Authorization = `Bearer ${token}`;
  return config;
});

client.interceptors.response.use(
  (res) => res,
  (err) => {
    // Never kick user to login page or clear session on 401
    return Promise.reject(err);
  }
);

export default client;
