import fs from 'fs';
import dotenv from "dotenv";
import NodeCache from 'node-cache';
import logger from './utils/logger.js';

// Initialize .ENV
dotenv.config();

// Initialize Logger
global.logger = logger;
global.config = {};
global.config.radius = {};
global.config.radius.secret =  process.env.RADIUS_SECRET;

// Certs
global.config.certs = {};
global.config.certs.ca = {};
global.config.certs.ca.publickey = fs.readFileSync("/workspaces/Visolity-WiFi/src/certs/ca/ca.pem");
global.config.certs.ca.privatekey = fs.readFileSync("/workspaces/Visolity-WiFi/src/certs/ca/ca.key");
global.config.certs.radius = {};
global.config.certs.radius.publickey = fs.readFileSync("/workspaces/Visolity-WiFi/src/certs/radius/radius.pem");
global.config.certs.radius.privatekey = fs.readFileSync("/workspaces/Visolity-WiFi/src/certs/radius/radius.key");


global.identities = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds
global.eapConnectionStates = new NodeCache({ useClones: false, stdTTL: 3600 }); // max for one hour
global.lastProcessedIdentifier = new NodeCache({ useClones: false, stdTTL: 60 });
global.openTLSSockets = new NodeCache({ useClones: false, stdTTL: 3600 }); // keep sockets for about one hour
global.queueData = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds
global.fragmentData = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds