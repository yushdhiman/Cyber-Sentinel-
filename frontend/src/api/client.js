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
  const token = localStorage.getItem('cs_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

client.interceptors.response.use(
  (res) => res,
  async (err) => {
    const originalRequest = err.config;

    if (err.response?.status === 401 && !originalRequest?._retry) {
      const isAuthEndpoint =
        originalRequest?.url?.includes('/auth/login') ||
        originalRequest?.url?.includes('/auth/register') ||
        originalRequest?.url?.includes('/auth/refresh');

      if (!isAuthEndpoint) {
        const refreshToken = localStorage.getItem('cs_refresh_token');
        if (refreshToken) {
          if (isRefreshing) {
            return new Promise((resolve, reject) => {
              failedQueue.push({ resolve, reject });
            })
              .then((token) => {
                originalRequest.headers.Authorization = `Bearer ${token}`;
                return client(originalRequest);
              })
              .catch((e) => Promise.reject(e));
          }

          originalRequest._retry = true;
          isRefreshing = true;

          try {
            const { data } = await axios.post(`${getBaseUrl()}/auth/refresh`, { refreshToken });
            if (data.token) {
              localStorage.setItem('cs_token', data.token);
              if (data.refreshToken) {
                localStorage.setItem('cs_refresh_token', data.refreshToken);
              }
              processQueue(null, data.token);
              originalRequest.headers.Authorization = `Bearer ${data.token}`;
              return client(originalRequest);
            }
          } catch (refreshErr) {
            processQueue(refreshErr, null);
            localStorage.removeItem('cs_token');
            localStorage.removeItem('cs_refresh_token');
            localStorage.removeItem('cs_user');
            if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
              window.location.href = '/login';
            }
            return Promise.reject(refreshErr);
          } finally {
            isRefreshing = false;
          }
        } else {
          localStorage.removeItem('cs_token');
          localStorage.removeItem('cs_refresh_token');
          localStorage.removeItem('cs_user');
          if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
            window.location.href = '/login';
          }
        }
      }
    }
    return Promise.reject(err);
  }
);

export default client;
