import './conf/config.js';
import webserver from './webenrollment/server.js'
import radiusserver from './radius/server.js';
import msGraphHandler from './msGraph/msGraphHandler.js';

logger.info('[Main] Starting Visolity WiFi Authenticator');

// Get Users from Azure
msGraphHandler.fetchAzureADUsers();

// Custom EAP-TLS Radius Server 
radiusserver.start();

// Webserver for user Enrollment
webserver.start(); 