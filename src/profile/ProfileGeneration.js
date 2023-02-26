import fs from 'fs';

class ProfileGeneration {
	
	static Create(name, username, platform) {

		// p12 data in base64 voor username
		const p12path = `src/certs/users/${username}.rawp12`
        const rawp12 = fs.readFileSync(p12path, 'utf8')
        const p12file = JSON.parse(rawp12);
		const base64p12 = p12file.p12encoded

		// Template config
		const path = `src/profile/${platform}/template.xml`
        const template = fs.readFileSync(path, 'utf8')

		const mod1 = template.replace("BASE64P12", base64p12);
		const payload = mod1.replace("USERNAME", name);

		return payload;
	}
}

export default ProfileGeneration;