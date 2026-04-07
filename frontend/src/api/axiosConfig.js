import axios from 'axios';

/**
 * centralized axios instance with relative base path.
 * Nginx will proxy /api requests to the backend.
 */
const api = axios.create({
    baseURL: '/api',
    withCredentials: true,
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json'
    }
});

export default api;
