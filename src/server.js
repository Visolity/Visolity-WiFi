import './config.js';
import webserver from './webserver/server.js'
import radiusserver from './radius/server.js';

logger.info('[Main] Starting Visolity WiFi Authenticator');

// Custom EAP-TLS Radius Server 
radiusserver.start();

// Webserver for user Enrollment
webserver.start(); 