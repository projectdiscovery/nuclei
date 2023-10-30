/**@module net */

/**
 * @class
 * @classdesc NetConn is a connection to a remote host.
 */
class NetConn {
    /**
    * @method
    * @description Close closes the connection.
    * @throws {error} - The error encountered during connection closing.
    * @example
    * let m = require('nuclei/net');
    * let c = m.Open('tcp', 'localhost:8080');
    * c.Close();
    */
    Close() {
        // implemented in go
    };

    /**
    * @method
    * @description Recv receives data from the connection with a timeout. If N is 0, it will read all available data.
    * @param {number} [N=0] - The number of bytes to receive.
    * @returns {Uint8Array} - The received data in an array.
    * @throws {error} - The error encountered during data receiving.
    * @example
    * let m = require('nuclei/net');
    * let c = m.Open('tcp', 'localhost:8080');
    * let data = c.Recv(1024);
    */
    Recv(N) {
        // implemented in go
    };

    /**
    * @method
    * @description RecvHex receives data from the connection with a timeout in hex format. If N is 0, it will read all available data.
    * @param {number} [N=0] - The number of bytes to receive.
    * @returns {string} - The received data in hex format.
    * @throws {error} - The error encountered during data receiving.
    * @example
    * let m = require('nuclei/net');
    * let c = m.Open('tcp', 'localhost:8080');
    * let data = c.RecvHex(1024);
    */
    RecvHex(N) {
        // implemented in go
    };

    /**
    * @method
    * @description RecvString receives data from the connection with a timeout. Output is returned as a string. If N is 0, it will read all available data.
    * @param {number} [N=0] - The number of bytes to receive.
    * @returns {string} - The received data as a string.
    * @throws {error} - The error encountered during data receiving.
    * @example
    * let m = require('nuclei/net');
    * let c = m.Open('tcp', 'localhost:8080');
    * let data = c.RecvString(1024);
    */
    RecvString(N) {
        // implemented in go
    };

    /**
    * @method
    * @description Send sends data to the connection with a timeout.
    * @param {Uint8Array} data - The data to send.
    * @throws {error} - The error encountered during data sending.
    * @example
    * let m = require('nuclei/net');
    * let c = m.Open('tcp', 'localhost:8080');
    * c.Send(new Uint8Array([1, 2, 3]));
    */
    Send(data) {
        // implemented in go
    };

    /**
    * @method
    * @description SendArray sends array data to connection.
    * @param {Uint8Array} data - The array data to send.
    * @throws {error} - The error encountered during data sending.
    * @example
    * let m = require('nuclei/net');
    * let c = m.Open('tcp', 'localhost:8080');
    * c.SendArray(new Uint8Array([1, 2, 3]));
    */
    SendArray(data) {
        // implemented in go
    };

    /**
    * @method
    * @description SendHex sends hex data to connection.
    * @param {string} data - The hex data to send.
    * @throws {error} - The error encountered during data sending.
    * @example
    * let m = require('nuclei/net');
    * let c = m.Open('tcp', 'localhost:8080');
    * c.SendHex('0x123');
    */
    SendHex(data) {
        // implemented in go
    };

    /**
    * @method
    * @description SetTimeout sets read/write timeout for the connection (in seconds).
    * @param {number} value - The timeout value in seconds.
    * @example
    * let m = require('nuclei/net');
    * let c = m.Open('tcp', 'localhost:8080');
    * c.SetTimeout(5);
    */
    SetTimeout(value) {
        // implemented in go
    };
};

/**
 * @function
 * @description Open opens a new connection to the address with a timeout. Supported protocols: tcp, udp.
 * @param {string} protocol - The protocol to use.
 * @param {string} address - The address to connect to.
 * @returns {NetConn} - The NetConn object representing the connection.
 * @throws {error} - The error encountered during connection opening.
 * @example
 * let m = require('nuclei/net'); 
 * let conn = m.Open('tcp', 'localhost:8080');
 */
function Open(protocol, address) {
    // implemented in go
};

/**
 * @function
 * @description OpenTLS opens a new connection to the address with a timeout. Supported protocols: tcp, udp.
 * @param {string} protocol - The protocol to use.
 * @param {string} address - The address to connect to.
 * @returns {NetConn} - The NetConn object representing the connection.
 * @throws {error} - The error encountered during connection opening.
 * @example
 * let m = require('nuclei/net'); 
 * let conn = m.OpenTLS('tcp', 'localhost:8080');
 */
function OpenTLS(protocol, address) {
    // implemented in go
};

module.exports = {
    NetConn: NetConn,
    Open: Open,
    OpenTLS: OpenTLS,
};