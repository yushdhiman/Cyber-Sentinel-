import axios from 'axios';

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
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
