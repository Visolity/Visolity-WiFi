import radius from "radius";
import dgram from "dgram";
import eaptlsHandler from "./eaptlsHandler.js";

var server = dgram.createSocket("udp4");

function makeid(length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function decodeEAPHeader(msg) {

    const code = msg.slice(0, 1).readUInt8(0);
    const identifier = msg.slice(1, 2).readUInt8(0);
    const length = msg.slice(2, 4).readUInt16BE(0);
    const type = msg.slice(4, 5).readUInt8(0);
    const data = msg.slice(5);

    return {
        code,
        identifier,
        length,
        type,
        data,
    };
}

async function handleMessage(msg) {

    const packet = radius.decode({ packet: msg, secret: config.radius.secret });

    // Alleen geinstereseerd in Access-Request en EAP Berichten
    if (packet.code !== 'Access-Request' && packet.attributes["EAP-Message"]) {
        console.log('[Radius] unknown packet type: ', packet.code);
        return undefined;
    }

    const stateID = (packet.attributes.State && packet.attributes.State.toString()) || makeid(16);

    // EAP MESSAGE
    let EAPmessage = packet.attributes['EAP-Message'];
    
    if (Array.isArray(EAPmessage) && !(packet.attributes['EAP-Message'] instanceof Buffer)) {
        logger.debug('[Radius] Multiple EAP Messages received, concat', EAPmessage.length);
        const allMsgs = EAPmessage;
        EAPmessage = Buffer.concat(allMsgs);
    }

    const EAPheader = decodeEAPHeader(EAPmessage);

    var response;

    switch (EAPheader.code) {
        case 1: // request
        case 2: // response
            switch (EAPheader.type) {
                case 1: // EAP identifiy
                    identities.set(stateID, EAPheader.data); // use token til binary 0.);
                    logger.info(`[Radius] EAP Request | Type: Identify | User: ${packet.attributes['User-Name']} | Session: (${stateID})`);

                    // Identify and Request EAP-TLS (13)
                    response = eaptlsHandler.buildEAPTLSResponse(EAPheader.identifier, 13, 0x20, stateID);
                    break;
                case 3: // NAK
                    logger.debug('[Radius] got NAK', EAPheader.data);
                    response = { code: "Access-Reject", };
                    break;
                case 13: // EAP-TLS
                    logger.debug(`[Radius] EAP-TLS Request | Type: xx | User: ${packet.attributes['User-Name']} | Session: (${stateID})`);
                    response = await eaptlsHandler.handleTLSmessage(EAPheader.identifier, stateID, EAPmessage, packet);
                    break;
                default: 
                    response = { code: "Access-Reject", }; // We doen alleen EAP-TLS (13)
            }
    }

    // still no response, we are done here
    if (!response || !response.code) {
        return undefined;
    }

    // all fine, return radius encoded response
    return radius.encode_response({
        packet,
        code: response.code,
        secret: config.radius.secret,
        attributes: response.attributes,
    });
}

const radiusserver = {};

radiusserver.start = async () => {

    // Radius Bericht Afhandelen
    server.on("message", async (msg, rinfo) => {

        const rsp = await handleMessage(msg);
        if (rsp) {
            server.send(rsp, 0, rsp.length, rinfo.port, rinfo.address, (err, _bytes) => {
                if (err) {
                    logger.info('[Radius] Error sending response to ', rinfo);
                }
            });
        }
    });

    logger.info('[Radius] Starting Radius EAP-TLS Server on port 1812');
    server.bind(1812);
};

export default radiusserver;