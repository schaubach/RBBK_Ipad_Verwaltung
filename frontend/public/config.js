// config.js - Environment Configuration
// This file is loaded before React and provides environment detection

(function() {
    'use strict';
    
    // Detect environment based on hostname
    var hostname = window.location.hostname;
    var protocol = window.location.protocol;
    
    var isEmergent = hostname.includes('emergentagent.com') || hostname.includes('preview.emergent');
    var isProduction = hostname.includes('rbbk-do.de') || hostname.includes('rbbk.de');
    var isLocalDev = hostname === 'localhost' || hostname === '127.0.0.1';
    
    // Environment configuration
    var config = {
        // Environment type
        environment: isProduction ? 'production' : (isEmergent ? 'emergent' : (isLocalDev ? 'development' : 'unknown')),
        
        // Is this the Emergent preview environment?
        isEmergent: isEmergent,
        
        // Is this the production environment?
        isProduction: isProduction,
        
        // Is this local development?
        isLocalDev: isLocalDev,
        
        // Should use HTTPS?
        useHttps: protocol === 'https:' || isProduction,
        
        // Session timeout in milliseconds (30 minutes)
        sessionTimeout: 30 * 60 * 1000,
        
        // Session warning before timeout (5 minutes before)
        sessionWarning: 5 * 60 * 1000,
        
        // API Base URL (will be overridden by REACT_APP_BACKEND_URL if set)
        apiBaseUrl: isProduction 
            ? 'https://ipad.rbbk-do.de/api'
            : (isEmergent 
                ? '' // Will use REACT_APP_BACKEND_URL
                : 'http://localhost:8001/api'),
        
        // Security settings
        security: {
            // Content Security Policy is handled in index.html meta tag
            enforceHttps: isProduction,
            
            // Certificate info for production
            certificate: {
                issuer: 'rbbk-do.de',
                location: 'Dortmund',
                organization: 'Robert-Bosch-Berufskolleg'
            }
        },
        
        // Logging level
        logLevel: isProduction ? 'error' : 'debug',
        
        // Feature flags
        features: {
            debugMode: !isProduction,
            showEnvironmentBadge: !isProduction,
            enableDetailedErrors: !isProduction
        }
    };
    
    // Make config globally available
    window.APP_CONFIG = config;
    
    // Log environment info (only in non-production)
    if (!isProduction) {
        console.log('[Config] Environment:', config.environment);
        console.log('[Config] Hostname:', hostname);
        console.log('[Config] Protocol:', protocol);
    }
    
    // Enforce HTTPS in production
    if (config.security.enforceHttps && protocol !== 'https:' && !isLocalDev) {
        console.warn('[Security] Redirecting to HTTPS...');
        window.location.href = 'https://' + hostname + window.location.pathname + window.location.search;
    }
})();
