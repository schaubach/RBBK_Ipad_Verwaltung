// Runtime Configuration - Same-Origin API
// Diese Datei wird zur Laufzeit geladen, nicht zur Build-Zeit!
//
// DOCKER/INTRANET: Relative URLs (Same-Origin)
//   - Frontend und Backend auf gleichem Host/Port (Nginx Reverse Proxy)
//   - /api/* wird zu Backend (Port 8001) weitergeleitet
//   - CORS nicht nötig, CSP: connect-src 'self'
//
// EMERGENT-PREVIEW: Absolute URLs (Cross-Origin)
//   - Frontend und Backend auf verschiedenen Hosts
//   - CORS erforderlich

window.getBackendURL = function() {
  var hostname = window.location.hostname;
  var port = window.location.port;

  // Emergent Preview Detection (nur hier Cross-Origin)
  if (hostname.includes('preview.emergentagent.com') || hostname.includes('preview.emergent') || hostname.includes('emergentagent.com')) {
    // Emergent-Preview: Verwende die Build-Zeit URL aus REACT_APP_BACKEND_URL
    // Diese wird bereits in App.js gelesen
    console.log('[Config] Emergent Preview detected - using REACT_APP_BACKEND_URL');
    return null; // null = verwende REACT_APP_BACKEND_URL
  }

  // Docker/Intranet: Same-Origin mit relativen URLs
  // Port 80/443 oder kein Port = Nginx Reverse Proxy aktiv
  if (!port || port === '80' || port === '443') {
    console.log('[Config] Docker/Intranet detected - using Same-Origin API');
    console.log('[Config] API calls will use relative URLs: /api/*');
    return '';  // Leerer String = relative URLs
  }

  // Lokale Entwicklung (z.B. localhost:3000)
  // Direkter Zugriff auf Backend
  var protocol = window.location.protocol;
  var url = protocol + '//' + hostname + ':8001';
  console.log('[Config] Development mode - using direct backend:', url);
  return url;
};

// Session Timeout Configuration
window.SESSION_CONFIG = {
  timeout: 30 * 60 * 1000,  // 30 Minuten in Millisekunden
  warning: 5 * 60 * 1000    // Warnung 5 Minuten vor Ablauf
};

// Environment Detection
window.APP_ENV = (function() {
  var hostname = window.location.hostname;
  
  if (hostname.includes('emergentagent.com') || hostname.includes('preview.emergent')) {
    return 'emergent';
  } else if (hostname.includes('rbbk-do.de') || hostname.includes('rbbk.de')) {
    return 'production';
  } else if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'development';
  }
  return 'unknown';
})();

console.log('[Config] Environment:', window.APP_ENV);
console.log('[Config] Config.js loaded - Smart API configuration ready');
