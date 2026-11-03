import axios from 'axios';
import { io } from 'socket.io-client';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';
const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || window.location.origin;

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Attach Bearer token from sessionStorage
apiClient.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('aegis_access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let socketInstance = null;

export function getSocket() {
  if (!socketInstance) {
    socketInstance = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      autoConnect: true
    });
  }
  return socketInstance;
}

export default apiClient;
