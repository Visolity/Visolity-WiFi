import fs from 'fs';
import dotenv from "dotenv";
import NodeCache from 'node-cache';
import logger from './utils/logger.js';

// Initialize .ENV
dotenv.config();

// Initialize Logger
global.logger = logger;

// Config
global.config = {};
config.radius = {};
config.radius.secret =  process.env.RADIUS_SECRET;

// Certs
config.certs = {};
config.certs.ca = {};
config.certs.ca.publickey = fs.readFileSync("src/certs/ca/ca.pem");
config.certs.ca.privatekey = fs.readFileSync("src/certs/ca/ca.key");
config.certs.radius = {};
config.certs.radius.publickey = fs.readFileSync("src/certs/radius/radius.pem");
config.certs.radius.privatekey = fs.readFileSync("src/certs/radius/radius.key");

// NodeCache
global.identities = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds
global.lastProcessedIdentifier = new NodeCache({ useClones: false, stdTTL: 60 });
global.queueData = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds
global.fragmentData = new NodeCache({ useClones: false, stdTTL: 60 }); // queue data maximum for 60 seconds
global.openTLSSockets = new NodeCache({ useClones: false, stdTTL: 3600 }); // keep sockets for about one hour
global.eapConnectionStates = new NodeCache({ useClones: false, stdTTL: 3600 }); // max for one hour