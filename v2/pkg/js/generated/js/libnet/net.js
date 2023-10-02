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
     * // Close the connection
     * let conn = Open('tcp', 'localhost:80');
     * conn.Close();
     */
    Close() {
        // implemented in go
    };

    /**
     * @method
     * @description Recv receives data from the connection with a timeout. If N is 0, it will read up to 4096 bytes.
     * @param {number} N - The number of bytes to receive.
     * @returns {Array} The received bytes.
     * @throws {Error} If an error occurred while receiving data.
     * @example
     * // Receive data
     * let conn = Open('tcp', 'localhost:80');
     * let data = conn.Recv(10); // Receive 10 bytes
     * log(data);
     */
    Recv(N) {
        // implemented in go
    };

    /**
     * @method
     * @description RecvHex receives data from the connection with a timeout in hex format. If N is 0, it will read up to 4096 bytes.
     * @param {number} N - The number of bytes to receive.
     * @returns {string} The received data in hex format.
     * @throws {Error} If an error occurred while receiving data.
     * @example
     * // Receive data in hex format
     * let conn = Open('tcp', 'localhost:80');
     * let data = conn.RecvHex(10); // Receive 10 bytes
     * log(data);
     */
    RecvHex(N) {
        // implemented in go
    };

    /**
     * @method
     * @description RecvString receives data from the connection with a timeout. Output is returned as a string. If N is 0, it will read up to 4096 bytes.
     * @param {number} N - The number of bytes to receive.
     * @returns {string} The received data as a string.
     * @throws {Error} If an error occurred while receiving data.
     * @example
     * // Receive data
     * let conn = Open('tcp', 'localhost:80');
     * let data = conn.RecvString(10); // Receive 10 bytes
     * log(data);
     */
    RecvString(N) {
        // implemented in go
    };

    /**
     * @method
     * @description Send sends data to the connection with a timeout.
     * @param {string} data - The data to send.
     * @throws {Error} If an error occurred while sending data.
     * @example
     * // Send data
     * let conn = Open('tcp', 'localhost:80');
     * conn.Send('Hello World!');
     */
    Send(data) {
        // implemented in go
    };

    /**
     * @method
     * @description SendArray sends array data to connection.
     * @param {Array} data - The array data to send.
     * @throws {Error} If an error occurred while sending data.
     * @example
     * // Send array data
     * let conn = Open('tcp', 'localhost:80');
     * conn.SendArray([0xde, 0x0b]);
     */
    SendArray(data) {
        // implemented in go
    };

    /**
     * @method
     * @description SendHex sends hex data to connection.
     * @param {string} data - The hex data to send.
     * @throws {Error} If an error occurred while sending data.
     * @example
     * // Send hex data
     * let conn = Open('tcp', 'localhost:80');
     * conn.SendHex('0xde0b');
     */
    SendHex(data) {
        // implemented in go
    };

    /**
     * @method
     * @description SetTimeout sets read/write timeout for the connection (in seconds).
     * @param {number} value - The timeout value in seconds.
     * @example
     * // Set timeout for connection
     * let conn = Open('tcp', 'localhost:80');
     * conn.SetTimeout(10); // 10 seconds
     */
    SetTimeout(value) {
        // implemented in go
    };
};

/**
 * @function
 * @description Open a connection with the specified protocol and address.
 * @param {string} protocol - The protocol to use.
 * @param {string} address - The address to connect to.
 * @example
 * // Open a connection
 * let conn = Open('tcp', 'localhost:80');
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
 * // Open a TLS connection
 * let conn = OpenTLS('tcp', 'localhost:443');
 */
function OpenTLS(protocol, address) {
    // implemented in go
};

module.exports = {
    NetConn: NetConn,
    Open: Open,
    OpenTLS: OpenTLS,
};