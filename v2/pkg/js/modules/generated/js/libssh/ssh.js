/**
 * @module ssh
 * This module implements bindings for ssh protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc SSHClient is a client for SSH servers. Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
 */
class SSHClient {
    /**
     * @method
     * @description Connect tries to connect to provided host and port with provided username and password with ssh.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @param {string} username - The username for authentication.
     * @param {string} password - The password for authentication.
     * @returns {boolean} Returns state of connection. If error is thrown, state will be false.
     * @throws Will throw an error if the connection fails.
     * @example
     * let client = new SSHClient();
     * client.Connect('localhost', 22, 'root', 'password');
     */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
     * @typedef {Object} HandshakeLog
     * @description HandshakeLog is a struct that contains information about the ssh connection.
     */

    /**
     * @method
     * @description ConnectSSHInfoMode tries to connect to provided host and port.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @returns {HandshakeLog} Returns HandshakeLog. If error is thrown, state will be false.
     * @throws Will throw an error if the connection fails.
     * @example
     * let client = new SSHClient();
     * client.ConnectSSHInfoMode('localhost', 22);
     */
    ConnectSSHInfoMode(host, port) {
        // implemented in go
    };

    /**
     * @method
     * @description ConnectWithKey tries to connect to provided host and port with provided username and private_key.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @param {string} username - The username for authentication.
     * @param {string} key - The private key for authentication.
     * @returns {boolean} Returns state of connection. If error is thrown, state will be false.
     * @throws Will throw an error if the connection fails.
     * @example
     * let client = new SSHClient();
     * client.ConnectWithKey('localhost', 22, 'root', 'private_key');
     */
    ConnectWithKey(host, port, username, key) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    SSHClient: SSHClient,
};