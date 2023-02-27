import ca from '../crypto/ca.js';
import msGraphHandler from '../msGraph/msGraphHandler.js';
import { encodeTunnelPW, startTLSServer } from '../crypto/tlsserver.js';

function tlsHasExportKeyingMaterial(tlsSocket) {
    return typeof tlsSocket.exportKeyingMaterial === 'function';
}

let MAX_RADIUS_ATTRIBUTE_SIZE = 253;
const eaptlsHandler = {};

const newDeferredPromise = () => {
    if (Promise && !('deferred' in Promise)) {
        let fResolve;
        let fReject;
        const P = new Promise((resolve, reject) => {
            fResolve = resolve;
            fReject = reject;
        });
        return {
            promise: P,
            resolve: fResolve,
            reject: fReject,
        };
    }
    return Promise.deferred;
};

eaptlsHandler.buildEAP = (identifier, msgType = EAPMessageType.TLS, msgFlags = 0x00, stateID, data, newResponse = true, maxSize = (MAX_RADIUS_ATTRIBUTE_SIZE - 5) * 4) => {

    /* it's the first one and we have more, therefore include length */
    const includeLength = maxSize > 0 && data && newResponse && data.length > maxSize;
    // extract data party
    const dataToSend = maxSize > 0 ? data && data.length > 0 && data.slice(0, maxSize) : data;
    const dataToQueue = maxSize > 0 && data && data.length > maxSize && data.slice(maxSize);
    /*
        0 1 2 3 4 5 6 7 8
        +-+-+-+-+-+-+-+-+
        |L M R R R R R R|
        +-+-+-+-+-+-+-+-+
  
        L = Length included
        M = More fragments
        R = Reserved
  
        The L bit (length included) is set to indicate the presence of the
        four-octet TLS Message Length field, and MUST be set for the first
        fragment of a fragmented TLS message or set of messages.  The M
        bit (more fragments) is set on all but the last fragment.
                Implementations of this specification MUST set the reserved bits
        to zero, and MUST ignore them on reception.
    */
    const flags = msgFlags +
        (includeLength ? 0b10000000 : 0) + // set L bit
        (dataToQueue && dataToQueue.length > 0 ? 0b01000000 : 0); // we have more data to come, set M bit
    let buffer = Buffer.from([
        1,
        identifier + 1,
        0,
        0,
        msgType,
        flags, // flags: 000000 (L include lenghts, M .. more to come)
    ]);
    // append length
    if (includeLength && data) {
        const length = Buffer.alloc(4);
        length.writeInt32BE(data.byteLength, 0);
        buffer = Buffer.concat([buffer, length]);
    }
    // build final buffer with data
    const resBuffer = dataToSend ? Buffer.concat([buffer, dataToSend]) : buffer;
    // set EAP length header
    resBuffer.writeUInt16BE(resBuffer.byteLength, 2);

    console.log('<<<<<<<<<<<< EAP RESPONSE TO CLIENT', {
        code: 1,
        identifier: identifier + 1,
        includeLength,
        dataLength: (data && data.byteLength) || 0,
        msgType: msgType.toString(10),
        flags: `00000000${flags.toString(2)}`.substr(-8),
        data,
    });
    return resBuffer;
}


eaptlsHandler.decodeEAPmessage = (msg) => {

    /* EAP TLS
     0               1               2             3
     1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 0 1 2 3 4 5 6 7 8  
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Code      |   Identifier  |            Length             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     4               5               6             7
     |     Type      |     Flags     |      TLS Message Length
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     8               9              10            11                
     |     TLS Message Length        |       TLS Data...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    const identifier = msg.slice(1, 2).readUInt8(0);
    const flags = msg.slice(5, 6).readUInt8(0); // .toString('hex');
    /*
    0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | L | M | S | R | R | R | R | R |
    +---+---+---+---+---+---+---+---+
  
    L = Length included
    M = More fragments
    S = Start
    R = Reserved
    */
    const decodedFlags = {
        // L
        lengthIncluded: !!(flags & 0b10000000),
        // M
        moreFragments: !!(flags & 0b01000000),
        // S
        start: !!(flags & 0b00100000),
        // R
        reserved: flags & 0b0001111,
    };
    let msglength;
    if (decodedFlags.lengthIncluded) {
        msglength = msg.slice(6, 10).readUInt32BE(0); // .readDoubleLE(0); // .toString('hex');
    }
    const data = msg.slice(decodedFlags.lengthIncluded ? 10 : 6).slice(0, msglength);

    /*
    console.log('>>>>>>>>>>>> REQUEST FROM CLIENT: EAP TLS', {
        flags: `00000000${flags.toString(2)}`.substr(-8),
        decodedFlags,
        identifier,
        msglengthBuffer: msg.length,
        msglength,
        data,
        //dataStr: data.toString()
    });
        */

    return {
        decodedFlags,
        msglength,
        data,
    };
}

eaptlsHandler.authResponse = (identifier, socket, packet) => {

    var authenticated = false;
    logger.info(`[EAP-TLS] ${packet.code} | User: ${packet.attributes['User-Name']} | NAS-IP: ${packet.attributes['NAS-IP-Address']}`);

    // TLS Sessie??
    if (socket != null) {

        var user_cert = socket.getPeerCertificate();
        logger.info(`[EAP-TLS][CN=${user_cert.subject["CN"]}] Client Cert CN: ${user_cert.subject["CN"]} | emailAddress: ${user_cert.subject["emailAddress"]}`);

        // UserCert validation against CA
        if (ca.ValidateUserCert(user_cert.raw.toString('base64')) === true) {
    
            // User validation against azure Graph 
            if (msGraphHandler.ValidateUser(user_cert.subject) === true) {
                authenticated = true // AUTH success
            }
    
        }
    }
    
    // EAP Response
    const buffer = Buffer.from([
        authenticated ? 3 : 4,
        identifier,
        0,
        4, //  length (2/2)
    ]);
    const attributes = [];
    attributes.push(['EAP-Message', buffer]);
    attributes.push(['User-Name', packet.attributes['User-Name'].toString()]);

    if (authenticated === true) {

        const keyingMaterial = socket.exportKeyingMaterial(128, 'client EAP encryption');
        if (!packet.authenticator) {
            throw new Error('FATAL: no packet authenticator variable set');
        }

        attributes.push([
            'Vendor-Specific',
            311,
            [[16, encodeTunnelPW(keyingMaterial.slice(33, 65), packet.authenticator, config.radius.secret)]],
        ]); //  MS-MPPE-Send-Key
        attributes.push([
            'Vendor-Specific',
            311,
            [[17, encodeTunnelPW(keyingMaterial.slice(0, 32), packet.authenticator, config.radius.secret)]],
        ]); // MS-MPPE-Recv-Key
    }

    logger.info(`[EAP-TLS] Return ${authenticated ? "Access-Accept" : "Access-Reject"} | User: ${packet.attributes['User-Name']} | NAS-IP: ${packet.attributes['NAS-IP-Address']}`);
    return {
        code: authenticated ? "Access-Accept" : "Access-Reject",
        attributes,
    };
}

eaptlsHandler.handleTLSmessage = async (identifier, stateID, msg, packet) => {

    if (identifier === lastProcessedIdentifier.get(stateID)) {
        logger.info(`[Radius] ignoring message ${identifier}, because it's processing already... ${stateID}`);
        return {};
    }

    lastProcessedIdentifier.set(stateID, identifier);

    try {
        var { decodedFlags, msglength, data } = eaptlsHandler.decodeEAPmessage(msg);
        // check if no data package is there and we have something in the queue, if so.. empty the queue first
        if (!data || data.length === 0) {
            const queuedData = queueData.get(stateID);
            if (queuedData instanceof Buffer && queuedData.length > 0) {
                //console.log(`returning queued data for ${stateID}`);
                return eaptlsHandler.buildEAPTLSResponse(identifier, 13, 0x00, stateID, queuedData, false);
            }
            // !!!DIT KOMT ALLEEN VOOR BIJ ACCESS REQUEST NA GELDIGE TUNNEL!!!!
            //console.log(`empty data queue for ${stateID}`);
            //return {}
        }

        // DEBUG //
        //console.log(decodedFlags);
        //console.log(msglength);
        //console.log(packet.code)
        //console.log(packet.attributes)
        // DEBUG //

        // Fragemented Package. Gedeelte opslaan en ACK versturen.
        if (decodedFlags.moreFragments === true) {
            //console.log("FRAGMENT")
            if (decodedFlags.lengthIncluded != true) {
                var arr = [fragmentData.get(stateID), data];
                data = Buffer.concat(arr);
            }
            fragmentData.set(stateID, data);
            return eaptlsHandler.buildEAPTLSResponse(identifier, 13, 0x00, stateID) // ACK
        }
        if (decodedFlags.lengthIncluded === false && decodedFlags.moreFragments === false) {
            if (fragmentData.get(stateID)) {
                var arr = [fragmentData.get(stateID), data];
                data = Buffer.concat(arr);
                fragmentData.del(stateID);
            }
        }

        const sendResponsePromise = newDeferredPromise();

        let connection = openTLSSockets.get(stateID);
        if (!connection) {
            //console.log("NEW TLS SOCKET");
            connection = startTLSServer();
            openTLSSockets.set(stateID, connection);
            connection.events.on('end', () => {
                // cleanup socket
                //console.log('ENDING SOCKET');
                openTLSSockets.del(stateID);
                lastProcessedIdentifier.del(stateID);
            });
        } else {
            //console.log("existing")
            if (!data || data.length === 0) {
                //console.log("!!!! existing EMPTY !!!!")
                //console.log(packet.code)
                //console.log(packet.attributes)
                return eaptlsHandler.authResponse(identifier, connection.tls, packet);
                //sendResponsePromise.resolve(eaptlsHandler.authResponse(identifier, true, connection.tls, packet));

            }
        }

        let tlsbuf = Buffer.from([]);
        let sendChunk = Buffer.from([]);

        const responseHandler = (encryptedResponseData) => {
            // Parse TLS record header
            tlsbuf = Buffer.concat([tlsbuf, encryptedResponseData]);
            while (tlsbuf.length > 5) {
                if (tlsbuf.length < 5) {
                    // not even so much data to read a header
                    console.log(`Not enough data length! tlsbuf.length = ${tlsbuf.length} < 5`);
                    break;
                }
                // Parse TLS record header
                // https://datatracker.ietf.org/doc/html/rfc5246
                // SSL3_RT_CHANGE_CIPHER_SPEC      20   (x'14')
                // SSL3_RT_ALERT                   21   (x'15')
                // SSL3_RT_HANDSHAKE               22   (x'16')
                // SSL3_RT_APPLICATION_DATA        23   (x'17')
                // TLS1_RT_HEARTBEAT               24   (x'18')
                const tlsContentType = tlsbuf.readUInt8(0);
                // TLS1_VERSION           x'0301'
                // TLS1_1_VERSION         x'0302'
                // TLS1_2_VERSION         x'0303'
                const tlsVersion = tlsbuf.readUInt16BE(1);
                // Length of data in the record (excluding the header itself).
                const tlsLength = tlsbuf.readUInt16BE(3);
                logger.debug(`TLS contentType = ${tlsContentType} version = 0x${tlsVersion.toString(16)} tlsLength = ${tlsLength}, tlsBufLength = ${tlsbuf.length}`);
                
                if (tlsbuf.length < tlsLength + 5) {
                    console.log(`Not enough data length! tlsbuf.length < ${tlsbuf.length} < ${tlsLength + 5}`);
                    break;
                }

                // TLS Handhake Failure. Access-Reject
                if (tlsContentType === 21) {
                    logger.info(`[EAP-TLS] TLS Handshake Error. | User: ${packet.attributes['User-Name']} | Session: (${stateID})`);
                    return eaptlsHandler.authResponse(identifier, null, packet);
                }
                
                sendChunk = Buffer.concat([sendChunk, tlsbuf.slice(0, tlsLength + 5)]);
                tlsbuf = tlsbuf.slice(tlsLength + 5);

            }
            //console.log('Maybe it is end of TLS burst.', tlsbuf.length);
            //console.log(`sendChunk sz=${sendChunk.length}`);
            //console.log('complete');
            // send back...
            sendResponsePromise.resolve(eaptlsHandler.buildEAPTLSResponse(identifier, 13, 0x00, stateID, sendChunk));
        };

        /*
        const checkExistingSession = (isSessionReused) => {
            //console.log("!!!TLS secured!!")
            //if (isSessionReused) {
            //console.log('secured, session reused, accept auth!');
            //sendResponsePromise.resolve(eaptlsHandler.authResponse(identifier, true, connection.tls, packet));
            //}
        };*/

        /*
        const sessionAuthenticated = (cert) => {
            logger.info(`[EAP-TLS] Session Authenticated | User: ${cert.subject.CN} | email: ${cert.subject.emailAddress}`);
            const queuedData = queueData.get(stateID);
            if (queuedData instanceof Buffer && queuedData.length > 0) {
                console.log(`DATA BIJ AUTH SUCCESS!! ${stateID}`);
                //return eaptlsHandler.buildEAPTLSResponse(identifier, 13, 0x00, stateID, queuedData, false);
            }
            sendResponsePromise.resolve(eaptlsHandler.authResponse(identifier, true, connection.tls, packet));
            //console.log(cert)
            //console.log(cert.pubkey.toString('base64'))
        };*/

        // register event listeners
        connection.events.on('response', responseHandler);
        //connection.events.on('secured', checkExistingSession);
        // emit data to tls server
        connection.events.emit('decrypt', data);
        const responseData = await sendResponsePromise.promise;
        // cleanup
        connection.events.off('response', responseHandler);
        //connection.events.off('secured', checkExistingSession);
        //connection.events.off('secured');
        // send response
        return responseData; // this.buildEAPTTLSResponse(identifier, 21, 0x00, stateID, encryptedResponseData);
    }
    catch (err) {
        console.log('decoding of EAP-TTLS package failed', msg, err);
        return {
            code: "Access-Reject",
        };
    }
    finally {
        lastProcessedIdentifier.set(stateID, undefined);
    }

}

eaptlsHandler.buildEAPTLS = (identifier, msgType = EAPMessageType.TLS, msgFlags = 0x00, stateID, data, newResponse = true, maxSize = (MAX_RADIUS_ATTRIBUTE_SIZE - 5) * 4) => {
    //console.log('maxSize', data?.length, ' > ', maxSize);
    /* it's the first one and we have more, therefore include length */
    const includeLength = maxSize > 0 && data && newResponse && data.length > maxSize;
    // extract data party
    const dataToSend = maxSize > 0 ? data && data.length > 0 && data.slice(0, maxSize) : data;
    const dataToQueue = maxSize > 0 && data && data.length > maxSize && data.slice(maxSize);
    /*
        0 1 2 3 4 5 6 7 8
        +-+-+-+-+-+-+-+-+
        |L M R R R R R R|
        +-+-+-+-+-+-+-+-+

        L = Length included
        M = More fragments
        R = Reserved

        The L bit (length included) is set to indicate the presence of the
        four-octet TLS Message Length field, and MUST be set for the first
        fragment of a fragmented TLS message or set of messages.  The M
        bit (more fragments) is set on all but the last fragment.
                Implementations of this specification MUST set the reserved bits
        to zero, and MUST ignore them on reception.
    */
    const flags = msgFlags +
        (includeLength ? 0b10000000 : 0) + // set L bit
        (dataToQueue && dataToQueue.length > 0 ? 0b01000000 : 0); // we have more data to come, set M bit
    let buffer = Buffer.from([
        1,
        identifier + 1,
        0,
        0,
        msgType,
        flags, // flags: 000000 (L include lenghts, M .. more to come)
    ]);
    // append length
    if (includeLength && data) {
        const length = Buffer.alloc(4);
        length.writeInt32BE(data.byteLength, 0);
        buffer = Buffer.concat([buffer, length]);
    }
    // build final buffer with data
    const resBuffer = dataToSend ? Buffer.concat([buffer, dataToSend]) : buffer;
    // set EAP length header
    resBuffer.writeUInt16BE(resBuffer.byteLength, 2);

    /*
    console.log('<<<<<<<<<<<< EAP RESPONSE TO CLIENT', {
        code: 1,
        identifier: identifier + 1,
        includeLength,
        dataLength: (data && data.byteLength) || 0,
        msgType: '13',
        flags: `00000000${flags.toString(2)}`.substr(-8),
        data,
    });*/
    if (dataToQueue) {
        // we couldn't send all at once, queue the rest and send later
        queueData.set(stateID, dataToQueue);
    }
    else {
        queueData.del(stateID);
    }
    return resBuffer;
}

eaptlsHandler.buildEAPTLSResponse = (identifier, msgType, msgFlags = 0x00, stateID, data, newResponse = true) => {

    const resBuffer = eaptlsHandler.buildEAPTLS(identifier, msgType, msgFlags, stateID, data, newResponse);

    var attributes = [['State', Buffer.from(stateID)]];

    let sentDataSize = 0;
    do {
        if (resBuffer.length > 0) {
            attributes.push([
                'EAP-Message',
                resBuffer.slice(sentDataSize, sentDataSize + MAX_RADIUS_ATTRIBUTE_SIZE),
            ]);
            sentDataSize += MAX_RADIUS_ATTRIBUTE_SIZE;
        }
    } while (sentDataSize < resBuffer.length);

    return {
        code: "Access-Challenge",
        attributes,
    }
}

export default eaptlsHandler;