import fs from 'fs';
import ca from '../crypto/ca.js';

class ProfileGeneration {
	
	static Create(name, username) {

		const usercert = ca.getUserCert(username);	// User Cert
		const base64ca = config.certs.ca.publickey;	// CA cert

		const path = `src/profile/apple/template.xml`
        const template = fs.readFileSync(path, 'utf8')

		const mod1 = template.replace("var_USERCERT", usercert.p12encoded);
		const mod2 = mod1.replace("var_CACERT", base64ca.toString('base64'));
		const mod3 = mod2.replace("var_SSID", config.wlan.ssid);
		const payload = mod3.replace("var_USERNAME", name);

		return payload;
	}
}

export default ProfileGeneration;