/** @module ssh */

/**
 * @typedef {object} HandshakeLog
 * @description HandshakeLog is a struct that contains information about the ssh connection.
 */
const HandshakeLog = {};

/**
 * @class
 * @classdesc SSHClient is a client for SSH servers. Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
 */
class SSHClient {
    /**
    @method
    @description Close closes the SSH connection and destroys the client. Returns the success state and error. If error is not nil, state will be false.
    @returns {boolean} - The success state of the operation.
    @throws {error} - The error encountered during the operation.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    let state = c.Connect('localhost', 22, 'user', 'password');
    c.Close();
    */
    Close() {
        // implemented in go
    };

    /**
    @method
    @description Connect tries to connect to provided host and port with provided username and password with ssh. Returns state of connection and error. If error is not nil, state will be false.
    @param {string} host - The host to connect to.
    @param {number} port - The port to connect to.
    @param {string} username - The username for the connection.
    @param {string} password - The password for the connection.
    @returns {boolean} - The state of the connection.
    @throws {error} - The error encountered during the connection.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    let result = c.Connect('localhost', 22, 'user', 'password');
    */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
    @method
    @description ConnectSSHInfoMode tries to connect to provided host and port with provided host and port. Returns HandshakeLog and error. If error is not nil, state will be false.
    @param {string} host - The host to connect to.
    @param {number} port - The port to connect to.
    @returns {HandshakeLog} - The HandshakeLog object containing information about the ssh connection.
    @throws {error} - The error encountered during the connection.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    let result = c.ConnectSSHInfoMode('localhost', 22);
    */
    ConnectSSHInfoMode(host, port) {
        // implemented in go
    };

    /**
    @method
    @description ConnectWithKey tries to connect to provided host and port with provided username and private_key. Returns state of connection and error. If error is not nil, state will be false.
    @param {string} host - The host to connect to.
    @param {number} port - The port to connect to.
    @param {string} username - The username for the connection.
    @param {string} key - The private key for the connection.
    @returns {boolean} - The state of the connection.
    @throws {error} - The error encountered during the connection.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    let result = c.ConnectWithKey('localhost', 22, 'user', 'private_key');
    */
    ConnectWithKey(host, port, username, key) {
        // implemented in go
    };

    /**
    @method
    @description Run tries to open a new SSH session, then tries to execute the provided command in said session. Returns string and error. If error is not nil, state will be false. The string contains the command output.
    @param {string} cmd - The command to execute.
    @returns {string} - The output of the command.
    @throws {error} - The error encountered during the execution of the command.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    let result = c.Run('ls');
    */
    Run(cmd) {
        // implemented in go
    };
};

module.exports = {
    SSHClient: SSHClient,
};