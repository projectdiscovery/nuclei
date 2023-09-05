/**
 * libssh implements bindings for ssh protocol in javascript
 * to be used from nuclei scanner.
 * 
 * Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
 * @class
 */
class Client {
    /**
     * Connect tries to connect to provided host and port
     * with provided username and password with ssh.
     * 
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @param {string} username - The username for authentication.
     * @param {string} password - The password for authentication.
     * @returns {boolean} - Returns state of connection. If error occurs, an exception is thrown.
     */
    Connect(host, port, username, password) {
        // Implementation goes here
    };

    /**
     * ConnectSSHInfoMode tries to connect to provided host and port.
     * 
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @returns {Object} - Returns HandshakeLog. If error occurs, an exception is thrown.
     * 
     * HandshakeLog is a struct that contains information about the
     * ssh connection.
     */
    ConnectSSHInfoMode(host, port) {
        // Implementation goes here
    };

    /**
     * ConnectWithKey tries to connect to provided host and port
     * with provided username and private_key.
     * 
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @param {string} username - The username for authentication.
     * @param {string} key - The private key for authentication.
     * @returns {boolean} - Returns state of connection. If error occurs, an exception is thrown.
     */
    ConnectWithKey(host, port, username, key) {
        // Implementation goes here
    };
};

module.exports = {
    Client: Client,
};