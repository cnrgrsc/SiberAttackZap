import axios from 'axios';

// Use relative path for same-origin requests (nginx proxy handles routing)
const API_BASE_URL = process.env.REACT_APP_API_URL || window.location.origin;

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('siberZed_token') || localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    return response.data;
  },
  (error) => {
    if (error.response?.status === 401) {
      // Only redirect to login if it's an authentication endpoint
      // For other endpoints, let the calling code handle the error
      const url = error.config?.url || '';
      
      // Critical auth endpoints that should trigger logout
      const criticalAuthEndpoints = ['/simple-auth/validate', '/simple-auth/refresh', '/simple-auth/login'];
      const isCriticalAuthEndpoint = criticalAuthEndpoints.some(endpoint => url.includes(endpoint));
      
      if (isCriticalAuthEndpoint) {
        console.warn('🚨 Critical auth endpoint returned 401, logging out:', url);
        localStorage.removeItem('siberZed_token');
        localStorage.removeItem('siberZed_user');
        localStorage.removeItem('siberZed_refreshToken');
        localStorage.removeItem('auth_token');
        window.location.href = '/login';
      } else {
        // For non-critical endpoints (like /user/profile), just log the error
        // Let the calling code handle it gracefully
        console.warn('⚠️ 401 error on non-critical endpoint:', url);
      }
    }
    return Promise.reject(error);
  }
);

export { API_BASE_URL };
export default api;
