/** 
 * @module ikev2
 * This module implements bindings for ikev2 protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * @class
 * @description IKEMessage is the IKEv2 message. IKEv2 implements a limited subset of IKEv2 Protocol, specifically
 * the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.
 */
class IKEMessage {
    /**
     * @method
     * @description AppendPayload appends a payload to the IKE message
     * @param {Object} payload - The payload to be appended
     * @throws {Error} If the payload cannot be appended
     * @example
     * let ikeMessage = new IKEMessage();
     * ikeMessage.AppendPayload(payload);
     */
    AppendPayload(payload) {
        // implemented in go
    };

    /**
     * @method
     * @description Encode encodes the final IKE message
     * @returns {Array} The encoded IKE message
     * @throws {Error} If the message cannot be encoded
     * @example
     * let ikeMessage = new IKEMessage();
     * let encodedMessage = ikeMessage.Encode();
     */
    Encode() {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    IKEMessage: IKEMessage,
};