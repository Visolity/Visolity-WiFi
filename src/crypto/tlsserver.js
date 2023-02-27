import * as events from 'events';
import * as tls from 'tls';
import { createSecureContext } from 'tls';
import * as crypto from 'crypto';
import DuplexPair from 'native-duplexpair';
import C from 'constants';

const tlsOptions = {
    cert: config.certs.radius.publickey,
    key: [
        {
            pem: config.certs.radius.privatekey,
        },
    ],
    requestCert: true,
    //secureOptions: C.SSL_OP_NO_TICKET, 
}

export function startTLSServer() {
    const secureContext = createSecureContext(tlsOptions);
    const duplexpair = new DuplexPair();
    const emitter = new events.EventEmitter();
    const cleartext = new tls.TLSSocket(duplexpair.socket1, {
        secureContext,
        isServer: true,
        //enableTrace: true,
        requestCert: true,  // TLS EAP
    });
    
    const encrypted = duplexpair.socket2;
    
    // for older tls versions without ticketing support
    cleartext.on('newSession', (sessionId, sessionData, callback) => {
        console.log(`TLS new session (${sessionId.toString('hex')})`);
        //resumeSessions.set(sessionId.toString('hex'), sessionData);
        callback();
    });
    emitter.on('decrypt', (data) => {
        encrypted.write(data);
    });
    emitter.on('encrypt', (data) => {
        cleartext.write(data);
    });
    encrypted.on('data', (data) => {
        emitter.emit('response', data);
    });
    /*
    cleartext.on('secure', () => {
        const cipher = cleartext.getCipher();
        if (cipher) {
            logger.debug(`[EAP-TLS] TLS negotiated (${cipher.name}, ${cipher.version})`);
        }
        cleartext.on('data', (data) => {
            emitter.emit('incoming', data);
        });
        cleartext.once('close', (_data) => {
            logger.debug('cleartext close');
            emitter.emit('end');
        });
        cleartext.on('keylog', (line) => {
            logger.debug('############ KEYLOG #############', line);
            // cleartext.getTicketKeys()
        });
        logger.debug('[EAP-TLS] *********** new TLS connection established / secured ********');
        emitter.emit('secured', cleartext.isSessionReused());
    });
    */
    cleartext.on('error', (err) => {
        console.log('cleartext error', err);
        encrypted.destroy();
        cleartext.destroy(err);
        emitter.emit('end');
    });
    return {
        events: emitter,
        tls: cleartext,
    };
}

function md5Hex(buffer) {
    const hasher = crypto.createHash('md5');
    hasher.update(buffer);
    return hasher.digest(); // new Buffer(hasher.digest("binary"), "binary");
}

export function encodeTunnelPW(key, authenticator, secret) {
    // see freeradius TTLS implementation how to obtain "key"......
    // https://tools.ietf.org/html/rfc2548
    /**
     * Salt
     The Salt field is two octets in length and is used to ensure the
     uniqueness of the keys used to encrypt each of the encrypted
     attributes occurring in a given Access-Accept packet.  The most
     significant bit (leftmost) of the Salt field MUST be set (1).  The
     contents of each Salt field in a given Access-Accept packet MUST
     be unique.
     */
    const salt = crypto.randomBytes(2);
    // eslint-disable-next-line no-bitwise
    salt[0] |= 0b10000000; // ensure leftmost bit is set to 1
    /*
   String
   The plaintext String field consists of three logical sub-fields:
   the Key-Length and Key sub-fields (both of which are required),
   and the optional Padding sub-field.  The Key-Length sub-field is
   one octet in length and contains the length of the unencrypted Key
   sub-field.  The Key sub-field contains the actual encryption key.
   If the combined length (in octets) of the unencrypted Key-Length
   and Key sub-fields is not an even multiple of 16, then the Padding
   sub-field MUST be present.  If it is present, the length of the
   Padding sub-field is variable, between 1 and 15 octets.  The
   String field MUST be encrypted as follows, prior to transmission:

   Construct a plaintext version of the String field by concate-
   nating the Key-Length and Key sub-fields.  If necessary, pad
   the resulting string until its length (in octets) is an even
   multiple of 16.  It is recommended that zero octets (0x00) be
   used for padding.  Call this plaintext P.
   */
    let P = Buffer.concat([new Uint8Array([key.length]), key]); // + key + padding;
    // fill up with 0x00 till we have % 16
    while (P.length % 16 !== 0) {
        P = Buffer.concat([P, Buffer.from([0x00])]);
    }
    /*
   Call the shared secret S, the pseudo-random 128-bit Request
   Authenticator (from the corresponding Access-Request packet) R,
   and the contents of the Salt field A.  Break P into 16 octet
   chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
   ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
   Intermediate values b(1), b(2)...c(i) are required.  Encryption
   is performed in the following manner ('+' indicates
   concatenation):
   
      Zorn                         Informational                     [Page 21]

   RFC 2548      Microsoft Vendor-specific RADIUS Attributes     March 1999


   b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
   b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
   .                      .
   .                      .
   .                      .
   b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)

   The   resulting   encrypted   String   field    will    contain
   c(1)+c(2)+...+c(i).
   */
    const p = [];
    for (let i = 0; i < P.length; i += 16) {
        p.push(P.slice(i, i + 16));
    }
    const S = secret;
    const R = authenticator;
    const A = salt;
    let C;
    const c = {};
    const b = {};
    for (let i = 0; i < p.length; i++) {
        if (!i) {
            b[i] = md5Hex(Buffer.concat([Buffer.from(S), R, A]));
        }
        else {
            b[i] = md5Hex(Buffer.concat([Buffer.from(S), c[i - 1]]));
        }
        c[i] = Buffer.alloc(16); // ''; //p[i];
        for (let n = 0; n < p[i].length; n++) {
            // eslint-disable-next-line no-bitwise
            c[i][n] = p[i][n] ^ b[i][n];
        }
        C = C ? Buffer.concat([C, c[i]]) : c[i];
    }
    const bufferC = Buffer.from(C);
    return Buffer.concat([salt, bufferC]);
}