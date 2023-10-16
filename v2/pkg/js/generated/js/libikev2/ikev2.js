/** @module ikev2 */

/**
 * @class
 * @classdesc IKEMessage is the IKEv2 message. IKEv2 implements a limited subset of IKEv2 Protocol, specifically the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.
 */
class IKEMessage {
    /**
    * @method
    * @description AppendPayload appends a payload to the IKE message
    * @param {object} payload - The payload to append to the IKE message.
    * @example
    * let m = require('nuclei/ikev2');
    * let ike = m.IKEMessage();
    * ike.AppendPayload({data: 'test'});
    */
    AppendPayload(payload) {
        // implemented in go
    };

    /**
    * @method
    * @description Encode encodes the final IKE message
    * @returns {Uint8Array} - The encoded IKE message.
    * @throws {error} - The error encountered during encoding.
    * @example
    * let m = require('nuclei/ikev2');
    * let ike = m.IKEMessage();
    * let encoded = ike.Encode();
    */
    Encode() {
        // implemented in go
    };
};

module.exports = {
    IKEMessage: IKEMessage,
};