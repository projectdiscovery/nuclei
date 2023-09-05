/**
 * @module ikev2
 * @description ikev2 implements bindings for ikev2 protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @name IKEMessage
 * @description IKEv2 implements a limited subset of IKEv2 Protocol, specifically the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.
 */
class IKEMessage {
    /**
     * @method
     * @name AppendPayload
     * @description appends a payload to the IKE message
     * @param {Object} payload - The payload to append
     * @returns {void}
     * @example
     * let ikeMessage = new IKEMessage();
     * ikeMessage.AppendPayload(payload);
     */
    AppendPayload(payload) {
        return;
    };

    /**
     * @method
     * @name Encode
     * @description encodes the final IKE message
     * @returns {Array} - Returns an array of bytes
     * @throws {Error} If there is an error in encoding
     * @example
     * let ikeMessage = new IKEMessage();
     * try {
     *   let encodedMessage = ikeMessage.Encode();
     * } catch (error) {
     *   console.error(error);
     * }
     */
    Encode() {
        // Removed 'error' as errors are thrown, not returned
        return [];
    };
};


module.exports = {
    IKEMessage: IKEMessage,
};