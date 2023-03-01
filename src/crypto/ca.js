import forge from 'node-forge';
import fs from 'fs';

const makeNumberPositive = (hexString) => {
	let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);

	if (mostSignificativeHexDigitAsInt < 8) return hexString;

	mostSignificativeHexDigitAsInt -= 8
	return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1)
}

// Generate a random serial number for the Certificate
const randomSerialNumber = () => {
	return makeNumberPositive(forge.util.bytesToHex(forge.random.getBytesSync(20)));
}

// Get the Not Before Date for a Certificate (will be valid from 2 days ago)
const getCertNotBefore = () => {
	let twoDaysAgo = new Date(Date.now() - 60 * 60 * 24 * 2 * 1000);
	let year = twoDaysAgo.getFullYear();
	let month = (twoDaysAgo.getMonth() + 1).toString().padStart(2, '0');
	let day = twoDaysAgo.getDate();
	return new Date(`${year}-${month}-${day} 00:00:00Z`);
}

// Get Certificate Expiration Date (Valid for 365 Days)
const getCertNotAfter = (notBefore) => {
	let ninetyDaysLater = new Date(notBefore.getTime() + 60 * 60 * 24 * 365 * 1000);
	let year = ninetyDaysLater.getFullYear();
	let month = (ninetyDaysLater.getMonth() + 1).toString().padStart(2, '0');
	let day = ninetyDaysLater.getDate();
	return new Date(`${year}-${month}-${day} 23:59:59Z`);
}

const DEFAULT_C = 'NL';
const DEFAULT_ST = 'Drenthe';
const DEFAULT_L = 'Emmen';
const DEFAULT_ORG = 'Visolity';

class ca {

	static GetRootCA() {

		const pemCert = config.certs.ca.publickey;
		const pemKey = config.certs.ca.privatekey;

		// Return the PEM encoded cert and private key
		return { certificate: pemCert, privateKey: pemKey };
	}

	static getUserCert(user, claims = false, renew = false) {

		var usercert = '';
        const path = `src/certs/users/${user}.json`

			//Certificaat Aanwezig??
            if (fs.existsSync(path)) {
                const raw = fs.readFileSync(path, 'utf8')
                usercert = JSON.parse(raw);

                // Geldig tegen huidige CA en nog niet verlopen??
                if (ca.ValidateUserCert(usercert.certificate) === false || renew === true) {
					renew = usercert;
					usercert = '';
                }
            }

			// Certificaat niet aanwezig of verlopen
			if (usercert === '') {
                usercert = ca.CreateUserCert(
                    claims.name,
                    claims.preferred_username,
                    [claims.preferred_username],
					renew
					);
                fs.writeFileSync(path, JSON.stringify(usercert, null, 2))
            }
		
			
			return usercert;
	}

	static getRevokedUserCerts(user) {
        const path = `src/certs/users/${user}.json`
        const usercert = fs.readFileSync(path, 'utf8')
		const revoked = JSON.parse(usercert);
		return revoked.revokedcerts;
	}

	static ValidateUserCert(pem) {

		// CA ObjectStore
		let rootCAObject = this.GetRootCA();
		let caCert = forge.pki.certificateFromPem(rootCAObject.certificate);
		const caStore = forge.pki.createCaStore();
		caStore.addCertificate(caCert);

		// User Cert as forge object
		if (!pem.startsWith("-----")) {
			var tmp = pem;
			pem = '-----BEGIN CERTIFICATE-----\n' + tmp + '\n-----END CERTIFICATE-----';
		}
		var certificate = forge.pki.certificateFromPem(pem);
		var CN = certificate.subject.getField('CN').value;

		// Expired?
		const padding = 24 * 3600 * 1000;
		const now = new Date();
		if (now.getTime() + padding >= certificate.validity.notAfter.getTime()) {
			logger.info(`[Visolity-CA][CN=${CN}] Certificate Expired`);
			return false;
		}

		try {
			if (!forge.pki.verifyCertificateChain(caStore, [certificate])) {
				logger.info(`[Visolity-CA][CN=${CN}] Certificate is not verified by the provided CA chain.`);
				return false;
			}
		} catch (error) {
			logger.info(`[Visolity-CA][CN=${CN}] ${error.message}`);
			return false;
		}

		// ToDo: Revoked?
		/*
		var revokedcerts = ca.getRevokedUserCerts(certificate.subject.getField('E').value)
		
		revokedcerts.forEach((rcert) => {
			console.log("check")
			console.log(pem.toString().Replace("").Replace("\n", ""))	
			/*
			if (rcert.toString().Replace("\n", "") === pem.toString().Replace("\n", "")) {
				console.log('!!!!JA!!!!!')
			}
		});
		*/

		logger.info(`[Visolity-CA][CN=${CN}] User Certificate is valid.`);
		return true;
	}

	static CreateUserCert(hostCertCN, username, validDomains, renew = false) {
		if (!hostCertCN.toString().trim()) throw new Error('"hostCertCN" must be a String');
		if (!Array.isArray(validDomains)) throw new Error('"validDomains" must be an Array of Strings');

		let rootCAObject = this.GetRootCA();

		// Convert the Root CA PEM details, to a forge Object
		let caCert = forge.pki.certificateFromPem(rootCAObject.certificate);
		let caKey = forge.pki.privateKeyFromPem(rootCAObject.privateKey);

		// Create a new Keypair for the Host Certificate
		const hostKeys = forge.pki.rsa.generateKeyPair(2048);

		// Define the attributes/properties for the Host Certificate
		const attributes = [{
			shortName: 'C',
			value: DEFAULT_C
		}, {
			shortName: 'ST',
			value: DEFAULT_ST
		}, {
			shortName: 'L',
			value: DEFAULT_L
		}, {
			name: 'organizationName',
			value: DEFAULT_ORG
		}, {
			name: 'commonName',
			value: hostCertCN
		}, {
			name: 'emailAddress',
			value: username
		}];

		const extensions = [{
			name: 'basicConstraints',
			cA: false
		}, {
			name: 'subjectAltName',
			altNames: ''
		}];

		// Create an empty Certificate
		let newHostCert = forge.pki.createCertificate();

		// Set the attributes for the new Host Certificate
		newHostCert.publicKey = hostKeys.publicKey;
		newHostCert.serialNumber = randomSerialNumber();
		newHostCert.validity.notBefore = getCertNotBefore();
		newHostCert.validity.notAfter = getCertNotAfter(newHostCert.validity.notBefore);
		newHostCert.setSubject(attributes);
		newHostCert.setIssuer(caCert.subject.attributes);
		newHostCert.setExtensions(extensions);

		// Sign the new Host Certificate using the CA
		newHostCert.sign(caKey, forge.md.sha512.create());

		// Convert to PEM format
		let pemHostCert = forge.pki.certificateToPem(newHostCert);
		let pemHostKey = forge.pki.privateKeyToPem(hostKeys.privateKey);

		// generate p12
		//const certChain = pemHostCert + rootCAObject.certificate;
		const pkcsAsn1 = forge.pkcs12.toPkcs12Asn1(hostKeys.privateKey, pemHostCert, 'password', { algorithm: '3des' });

		const pkcsAsn1Bytes = forge.asn1.toDer(pkcsAsn1).getBytes();
		//const fs = require('fs')
		//fs.promises.writeFile('certs/cert.p12', pkcsAsn1Bytes, {encoding: 'binary'});

		const p12encoded = forge.util.encode64(pkcsAsn1Bytes); // Direct buffer which can be sent to s3

		var revokedcerts = [];

		if (renew != false) {
			revokedcerts.push(renew.certificate)
			revokedcerts.push(...renew.revokedcerts)
		}
		
		logger.info(`[Visolity-CA][CN=${hostCertCN}] New User Certificate created.`);

		return { 
			p12encoded: p12encoded, 
			certificate: pemHostCert, 
			privateKey: pemHostKey, 
			notAfter: newHostCert.validity.notAfter,
			revokedcerts: revokedcerts  
		};
	}
}

export default ca;