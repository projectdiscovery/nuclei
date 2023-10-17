/** @module ssh */

/**
 * @class
 * @classdesc SSHClient is a client for SSH servers. Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
 */
class SSHClient {
    /**
    * @method
    * @description Connect tries to connect to provided host and port with provided username and password with ssh. Returns state of connection and error. If error is not nil, state will be false.
    * @param {string} host - The host to connect to.
    * @param {number} port - The port to connect to.
    * @param {string} username - The username to use for connection.
    * @param {string} password - The password to use for connection.
    * @returns {boolean} - The state of the connection.
    * @throws {error} - The error encountered during connection.
    * @example
    * let m = require('nuclei/ssh');
    * let c = m.SSHClient();
    * let state = c.Connect('localhost', 22, 'user', 'password');
    */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
    * @method
    * @description ConnectSSHInfoMode tries to connect to provided host and port. Returns HandshakeLog and error. If error is not nil, state will be false. HandshakeLog is a struct that contains information about the ssh connection.
    * @param {string} host - The host to connect to.
    * @param {number} port - The port to connect to.
    * @returns {HandshakeLog} - The HandshakeLog object containing information about the ssh connection.
    * @throws {error} - The error encountered during connection.
    * @example
    * let m = require('nuclei/ssh');
    * let c = m.SSHClient();
    * let log = c.ConnectSSHInfoMode('localhost', 22);
    */
    ConnectSSHInfoMode(host, port) {
        // implemented in go
    };

    /**
    * @method
    * @description ConnectWithKey tries to connect to provided host and port with provided username and private_key. Returns state of connection and error. If error is not nil, state will be false.
    * @param {string} host - The host to connect to.
    * @param {number} port - The port to connect to.
    * @param {string} username - The username to use for connection.
    * @param {string} key - The private key to use for connection.
    * @returns {boolean} - The state of the connection.
    * @throws {error} - The error encountered during connection.
    * @example
    * let m = require('nuclei/ssh');
    * let c = m.SSHClient();
    * let state = c.ConnectWithKey('localhost', 22, 'user', 'key');
    */
    ConnectWithKey(host, port, username, key) {
        // implemented in go
    };
};

/**
 * @typedef {object} HandshakeLog
 * @description HandshakeLog is a object containing information about the ssh connection.
 */
const HandshakeLog = {};

module.exports = {
    SSHClient: SSHClient,
};