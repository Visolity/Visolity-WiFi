DH_KEY_SIZE	= 2048
OPENSSL		= openssl

#  Set the passwords
include passwords.mk

######################################################################
#  Make the necessary files, but not client certificates.
######################################################################
.PHONY: all
all: index.txt serial dh server ca

.PHONY: ca
ca: ca.pem

.PHONY: server
server: server.key server.vrfy

.PHONY: verify
verify: server.vrfy

passwords.mk: server.cnf ca.cnf
	@echo "PASSWORD_SERVER	= '$(shell grep output_password server.cnf | sed 's/.*=//;s/^ *//')'"		> $@
	@echo "PASSWORD_CA	= '$(shell grep output_password ca.cnf | sed 's/.*=//;s/^ *//')'"		>> $@
	@echo "CA_DEFAULT_DAYS  = '$(shell grep default_days ca.cnf | sed 's/.*=//;s/^ *//')'"			>> $@

######################################################################
#  Diffie-Hellman parameters
######################################################################
dh:
	$(OPENSSL) dhparam -out dh -2 $(DH_KEY_SIZE)

######################################################################
#  Create a new self-signed CA certificate
######################################################################
ca.key ca.pem: ca.cnf
	@[ -f index.txt ] || $(MAKE) index.txt
	@[ -f serial ] || $(MAKE) serial
	$(OPENSSL) req -new -x509 -keyout caenc.key -out ca.pem \
		-days $(CA_DEFAULT_DAYS) -config ./ca.cnf \
		-passin pass:$(PASSWORD_CA)
	$(OPENSSL) rsa -in caenc.key -passin pass:$(PASSWORD_CA) -out ca.key
	rm caenc.key
	chmod g+r ca.key

######################################################################
#  Create a new server certificate, signed by the above CA.
######################################################################
server.crt serverenc.key: ca.key server.cnf
	$(OPENSSL) req -new  -out server.csr -keyout serverenc.key -config ./server.cnf
	$(OPENSSL) ca -batch -keyfile ca.key -cert ca.pem -in server.csr  -key $(PASSWORD_CA) -out server.crt -extensions xpserver_ext -extfile xpextensions -config ./server.cnf
	rm server.csr
	chmod g+r serverenc.key

server.key server.pem: server.crt ca.key ca.pem
	$(OPENSSL) rsa -in serverenc.key -passin pass:$(PASSWORD_CA) -out radius.key
	$(OPENSSL) x509 -in server.crt -out radius.pem 
	rm serverenc.key
	rm server.crt
	rm 01.pem

.PHONY: server.vrfy
server.vrfy: ca.pem
	@$(OPENSSL) verify $(PARTIAL) -CAfile ca.pem radius.pem

######################################################################
#  Miscellaneous rules.
######################################################################
index.txt:
	@touch index.txt

serial:
	@echo '01' > serial

print:
	$(OPENSSL) x509 -text -in radius.pem

printca:
	$(OPENSSL) x509 -text -in ca.pem

clean:
	@rm -f *~ *old client.csr client.key client.crt client.p12 client.pem

#	Make a target that people won't run too often.
destroycerts:
	rm -f *~ dh *.csr *.crt *.p12 *.der *.pem *.key index.txt* \
			serial*  *\.0 *\.1 ca-crl.pem ca.crl
