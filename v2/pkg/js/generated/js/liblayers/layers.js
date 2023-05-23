// liblayers implements bindings for layers protocol in javascript
// to be used from nuclei scanner.

// IKEMessage is the IKEv2 message
// 
// IKEv2 implements a limited subset of IKEv2 Protocol, specifically
// the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.
class IKEMessage {
    // AppendPayload appends a payload to the IKE message
    AppendPayload(payload) {
        return;
    };
    // Encode encodes the final IKE message
    Encode() {
        return [] byte, error;
    };
};


module.exports = {
    IKEMessage: IKEMessage,
};