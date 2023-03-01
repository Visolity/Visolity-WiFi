import fs from 'fs';
import ca from '../crypto/ca.js';

class ProfileGeneration {
	
	static Create(name, username) {

		const usercert = ca.getUserCert(username);	// User Cert
		const base64ca = config.certs.ca.publickey;	// CA cert

		const path = `src/profile/apple/template.xml`
        const template = fs.readFileSync(path, 'utf8')

		const mod1 = template.replace("BASE64P12", usercert.p12encoded);
		const mod2 = mod1.replace("BASE64_CA", base64ca.toString('base64'));
		const payload = mod2.replace("USERNAME", name);

		return payload;
	}
}

export default ProfileGeneration;