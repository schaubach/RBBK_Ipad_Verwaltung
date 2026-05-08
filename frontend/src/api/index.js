import axios from 'axios';
import { toast } from 'sonner';

// Smart API Configuration
// - Docker/Intranet: Relative URLs (Same-Origin, kein CORS)
// - Emergent-Preview: Absolute URLs (Cross-Origin, CORS)
// - Lokale Entwicklung: Direkter Backend-Zugriff
const getRuntimeURL = typeof window !== 'undefined' && window.getBackendURL ? window.getBackendURL() : null;
const BACKEND_URL = getRuntimeURL !== null
  ? getRuntimeURL  // Runtime-Konfiguration (Docker/Dev)
  : (process.env.REACT_APP_BACKEND_URL || '');  // Build-Zeit URL (Emergent-Preview)

export const API_BASE_URL = BACKEND_URL ? `${BACKEND_URL}/api` : '/api';

// Environment Detection
export const APP_ENV = typeof window !== 'undefined' && window.APP_ENV ? window.APP_ENV : 'unknown';

// Session Timeout Configuration (30 minutes)
const SESSION_CONFIG = typeof window !== 'undefined' && window.SESSION_CONFIG 
  ? window.SESSION_CONFIG 
  : { timeout: 30 * 60 * 1000, warning: 5 * 60 * 1000 };

export const SESSION_TIMEOUT = SESSION_CONFIG.timeout;
export const SESSION_WARNING = SESSION_CONFIG.warning;

console.log('[App] API Base:', API_BASE_URL || '(relative - same origin)');
console.log('[App] Environment:', APP_ENV);
console.log('[App] Session Timeout:', SESSION_TIMEOUT / 60000, 'minutes');

// API configuration with HttpOnly Cookie support
const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,  // IMPORTANT: Send HttpOnly cookies with every request
});

// Request interceptor - still supports Bearer token for backwards compatibility
api.interceptors.request.use((config) => {
  // Legacy support: If token exists in localStorage, send it as Bearer
  // This will be phased out - HttpOnly cookie is preferred
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Flag um mehrfache Logout-Meldungen zu verhindern
let isLoggingOut = false;

// Response Interceptor für automatischen Logout bei Session-Ablauf
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401 && !isLoggingOut) {
      isLoggingOut = true;
      
      // Versuche den Logout-Endpoint aufzurufen um den HttpOnly Cookie zu löschen
      try {
        await axios.post(`${API_BASE_URL}/auth/logout`, {}, { withCredentials: true });
      } catch {
        // Ignoriere Fehler beim Logout
      }
      
      // Legacy: Token aus localStorage entfernen
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      localStorage.removeItem('role');
      localStorage.removeItem('lastActivity');
      
      // Zur Login-Seite weiterleiten (durch App-State-Reset)
      window.dispatchEvent(new CustomEvent('session-expired'));
      
      toast.error('Ihre Session ist abgelaufen. Bitte melden Sie sich erneut an.');
      
      // Flag nach kurzer Zeit zurücksetzen
      setTimeout(() => {
        isLoggingOut = false;
      }, 2000);
    }
    return Promise.reject(error);
  }
);

export default api;
