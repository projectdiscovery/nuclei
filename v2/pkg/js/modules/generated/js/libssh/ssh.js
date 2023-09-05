/**
 * @module ssh
 * @description ssh implements bindings for ssh protocol in javascript to be used from nuclei scanner.
 */

/**
 * @typedef {Object} HandshakeLog
 * @description A struct that contains information about the ssh connection.
 */

/**
 * @class
 * @description Client is a client for SSH servers. Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
 */
class Client {
    /**
     * @method
     * @description Connect tries to connect to provided host and port with provided username and password with ssh.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @param {string} username - The username for authentication.
     * @param {string} password - The password for authentication.
     * @returns {boolean} The state of the connection.
     * @throws {Error} If an error occurs during connection.
     * @example
     * const client = new Client();
     * client.Connect('localhost', 22, 'user', 'pass');
     */
    Connect(host, port, username, password) {
        // Implementation here...
    };

    /**
     * @method
     * @description ConnectSSHInfoMode tries to connect to provided host and port.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @returns {HandshakeLog} Information about the ssh connection.
     * @throws {Error} If an error occurs during connection.
     * @example
     * const client = new Client();
     * client.ConnectSSHInfoMode('localhost', 22);
     */
    ConnectSSHInfoMode(host, port) {
        // Implementation here...
    };

    /**
     * @method
     * @description ConnectWithKey tries to connect to provided host and port with provided username and private_key.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @param {string} username - The username for authentication.
     * @param {string} key - The private key for authentication.
     * @returns {boolean} The state of the connection.
     * @throws {Error} If an error occurs during connection.
     * @example
     * const client = new Client();
     * client.ConnectWithKey('localhost', 22, 'user', 'private_key');
     */
    ConnectWithKey(host, port, username, key) {
        // Implementation here...
    };
};

/**
 * @description Exports the Client class.
 */
module.exports = {
    Client: Client,
};