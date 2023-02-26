import fs from 'fs';
import express from 'express';
var router = express.Router();
import fetch from '../fetch.js'
import CertificateGeneration from '../../crypto/CertificateGeneration.js';
import ProfileGeneration from '../../profile/ProfileGeneration.js';

const GRAPH_ME_ENDPOINT = process.env.GRAPH_API_ENDPOINT + "v1.0/me";
import profile from 'console';

// custom middleware to check auth state
function isAuthenticated(req, res, next) {
    if (!req.session.isAuthenticated) {
        return res.redirect('/auth/signin'); // redirect to sign-in route
    }

    next();
};

router.get('/', 
    isAuthenticated, // check if user is authenticated
    async function (req, res, next) {

        var p12file = '';

        //Certificaat Aanwezig??
        const path = `src/certs/users/${req.session.account.idTokenClaims.preferred_username}.rawp12`

        try {
            if (fs.existsSync(path)) {
                const rawp12 = fs.readFileSync(path, 'utf8')
                p12file = JSON.parse(rawp12);
            }
            else {
                p12file = CertificateGeneration.CreateHostCert(
                    req.session.account.idTokenClaims.name,
                    req.session.account.idTokenClaims.preferred_username, 
                    [req.session.account.idTokenClaims.preferred_username]);
                fs.writeFileSync(path, JSON.stringify(p12file))
            }
        
        } catch(err) {
            console.error(err)
        }

        const claims = {
            name: req.session.account.idTokenClaims.name,
            preferred_username: req.session.account.idTokenClaims.preferred_username,
        }

        res.render('index', {
            claims: claims,
            p12file: p12file,
        });
    });

router.get('/download/',
    isAuthenticated, // check if user is authenticated
    
    async function (req, res, next) {

        if (req.query.type === 'apple') {
        
            const profile = ProfileGeneration.Create(req.session.account.idTokenClaims.name, req.session.account.idTokenClaims.preferred_username, req.query.type);
        
            res.contentType('text/plain');
            res.status(200)
            .attachment(`Visolity-Wifi.mobileconfig`)
            .send(profile)
        }

        else {

            const path = `src/certs/users/${req.session.account.idTokenClaims.preferred_username}.rawp12`

            const rawp12 = fs.readFileSync(path, 'utf8')
            const p12file = JSON.parse(rawp12);

            var pfx = new Buffer(p12file.p12encoded, 'base64');

            res.contentType('text/plain');
            res.status(200)
            .attachment(`${req.session.account.idTokenClaims.preferred_username}.pfx`)
            .send(pfx)
        }
    }
);

router.get('/profile',
    isAuthenticated, // check if user is authenticated
    async function (req, res, next) {
        try {
            const graphResponse = await fetch(GRAPH_ME_ENDPOINT, req.session.accessToken);
            res.render('profile', { profile: graphResponse });
        } catch (error) {
            next(error);
        }
    }
);

export default router;