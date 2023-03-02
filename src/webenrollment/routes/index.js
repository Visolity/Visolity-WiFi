import express from 'express';
import AdmZip from 'adm-zip';
var router = express.Router();
import ProfileGeneration from '../../profile/ProfileGeneration.js';
import ca from '../../crypto/ca.js';

// custom middleware to check auth state
function isAuthenticated(req, res, next) {
    if (!req.session.isAuthenticated) {
        return res.redirect('/auth/signin'); // redirect to sign-in route
    }

    next();
};

router.get(['/', '/renew'],
    isAuthenticated, // check if user is authenticated
    async function (req, res, next) {
        const renew = req.path === '/renew' ? true : false;

        res.render('index', {
            ssid: config.wlan.ssid,
            claims: req.session.account.idTokenClaims,
            usercert: ca.getUserCert(req.session.account.idTokenClaims.preferred_username, req.session.account.idTokenClaims, renew),
            cacert: config.certs.ca.publickey,
        });
    }
);

router.get('/download/',
    isAuthenticated, // check if user is authenticated
    async function (req, res, next) {
        var name;
        var payload;
        var contentType = 'text/plain';

        if (req.query.type === 'apple') {
            name = "Visolity-Wifi.mobileconfig";
            payload = ProfileGeneration.Create(req.session.account.idTokenClaims.name, req.session.account.idTokenClaims.preferred_username);
        }

        else {
            const usercert = ca.getUserCert(req.session.account.idTokenClaims.preferred_username);
            const pfx = new Buffer(usercert.p12encoded, 'base64');

            contentType = 'application/octet-stream';

            if (req.query.type === 'zip') {

                var zip = new AdmZip();
                zip.addFile(`${req.session.account.idTokenClaims.preferred_username}.pfx`, pfx, "PFX");
                zip.addFile("Visolity-Wifi-CA.crt", Buffer.from(config.certs.ca.publickey, "utf8"), "CA");

                name = "Visolity-Wifi-CertBundle.zip";
                payload = zip.toBuffer();
            }

            if (req.query.type === 'pfx') {
                name = `${req.session.account.idTokenClaims.preferred_username}.pfx`;
                payload = pfx
            }
        }
        res.set('Content-Type', contentType);
        res.status(200).attachment(name).send(payload)
    }
);

export default router;