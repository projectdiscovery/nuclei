/**
 * @fileoverview libikev2 implements bindings for ikev2 protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @description IKEMessage is the IKEv2 message. IKEv2 implements a limited subset of IKEv2 Protocol, specifically the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.
 */
class IKEMessage {
    /**
     * @method
     * @description AppendPayload appends a payload to the IKE message
     * @param {Object} payload - The payload to append
     */
    AppendPayload(payload) {
        // Implementation goes here
    };

    /**
     * @method
     * @description Encode encodes the final IKE message
     * @returns {Uint8Array} - The encoded IKE message
     */
    Encode() {
        // Implementation goes here
        return new Uint8Array();
    };
};

/**
 * @module
 * @description Exports the IKEMessage class
 */
module.exports = {
    IKEMessage: IKEMessage,
};