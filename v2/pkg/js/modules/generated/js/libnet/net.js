/**
 * @module net
 */

/**
 * @class
 * @classdesc NetConn is a connection to a remote host.
 */
class NetConn {
    /**
     * @method
     * @description Close closes the connection.
     * @throws {Error} If an error occurred while closing the connection.
     * @example
     * let netConn = new NetConn();
     * netConn.Close();
     */
    Close() {
        // implemented in go
    };

    /**
     * @method
     * @description Recv receives data from the connection with a timeout.
     * @param {number} timeout - The timeout duration.
     * @param {number} N - The number of bytes to receive.
     * @returns {Array} An array of bytes received from the connection.
     * @throws {Error} If an error occurred while receiving data.
     * @example
     * let netConn = new NetConn();
     * let data = netConn.Recv(5000, 1024);
     */
    Recv(timeout, N) {
        // implemented in go
    };

    /**
     * @method
     * @description Send sends data to the connection with a timeout.
     * @param {Array} data - The data to send.
     * @param {number} timeout - The timeout duration.
     * @throws {Error} If an error occurred while sending data.
     * @example
     * let netConn = new NetConn();
     * netConn.Send([1, 2, 3, 4], 5000);
     */
    Send(data, timeout) {
        // implemented in go
    };

    /**
     * @method
     * @description SendRecv sends data to the connection and receives data from the connection with a timeout.
     * @param {Array} data - The data to send.
     * @param {number} timeout - The timeout duration.
     * @returns {Array} An array of bytes received from the connection.
     * @throws {Error} If an error occurred while sending or receiving data.
     * @example
     * let netConn = new NetConn();
     * let response = netConn.SendRecv([1, 2, 3, 4], 5000);
     */
    SendRecv(data, timeout) {
        // implemented in go
    };
};

/**
 * @function
 * @description Open a connection with the specified protocol and address.
 * @param {string} protocol - The protocol to use.
 * @param {string} address - The address to connect to.
 * @example
 * Open('http', 'localhost:8080');
 */
function Open(protocol, address) {
    // implemented in go
};

/**
 * @function
 * @description Open a TLS connection with the specified protocol and address.
 * @param {string} protocol - The protocol to use.
 * @param {string} address - The address to connect to.
 * @example
 * OpenTLS('https', 'localhost:8443');
 */
function OpenTLS(protocol, address) {
    // implemented in go
};

// ReadOnly DONOT EDIT
module.exports = {
    NetConn: NetConn,
    Open: Open,
    OpenTLS: OpenTLS,
};