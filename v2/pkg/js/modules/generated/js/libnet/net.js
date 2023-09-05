/**
 * libnet implements bindings for net protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * Conn is a connection to a remote host.
 * @class
 */
class Conn {
    /**
     * Close closes the connection.
     * @throws {Error} If an error occurred while closing the connection.
     */
    Close() {
        throw new Error();
    };

    /**
     * Recv receives data from the connection with a timeout.
     * @param {number} timeout - The timeout duration.
     * @param {number} N - The number of data to receive.
     * @returns {Uint8Array} The received data.
     */
    Recv(timeout, N) {
        return Uint8Array;
    };

    /**
     * Send sends data to the connection with a timeout.
     * @param {Uint8Array} data - The data to send.
     * @param {number} timeout - The timeout duration.
     * @throws {Error} If an error occurred while sending the data.
     */
    Send(data, timeout) {
        throw new Error();
    };

    /**
     * SendRecv sends data to the connection and receives data from the connection with a timeout.
     * @param {Uint8Array} data - The data to send.
     * @param {number} timeout - The timeout duration.
     * @returns {Uint8Array} The received data.
     */
    SendRecv(data, timeout) {
        return Uint8Array;
    };
};

/**
 * Open a connection with the specified protocol and address.
 * @param {string} protocol - The protocol to use.
 * @param {string} address - The address to connect to.
 */
function Open(protocol, address) {

};

/**
 * Open a TLS connection with the specified protocol and address.
 * @param {string} protocol - The protocol to use.
 * @param {string} address - The address to connect to.
 */
function OpenTLS(protocol, address) {

};

module.exports = {
    Open: Open,
    OpenTLS: OpenTLS,
    NetConn: Conn,
};