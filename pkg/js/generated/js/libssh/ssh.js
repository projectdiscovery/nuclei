/**@module ssh */

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
    @description Close closes the SSH connection and destroys the client
    @returns {boolean} - The success state of the operation.
    @throws {error} - The error encountered during the operation.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    let state = c.Connect('localhost', 22, 'user', 'password');
    let result = c.Close();
    */
    Close() {
        // implemented in go
    };

    /**
    @method
    @description Connect tries to connect to provided host and port with provided username and password with ssh.
    @param {string} host - The host to connect to.
    @param {number} port - The port to connect to.
    @param {string} username - The username for the connection.
    @param {string} password - The password for the connection.
    @returns {boolean} - The success state of the operation.
    @throws {error} - The error encountered during the operation.
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
    @description ConnectSSHInfoMode tries to connect to provided host and port with provided host and port
    @param {string} host - The host to connect to.
    @param {number} port - The port to connect to.
    @returns {HandshakeLog} - The HandshakeLog object containing information about the ssh connection.
    @throws {error} - The error encountered during the operation.
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
    @description ConnectWithKey tries to connect to provided host and port with provided username and private_key.
    @param {string} host - The host to connect to.
    @param {number} port - The port to connect to.
    @param {string} username - The username for the connection.
    @param {string} key - The private key for the connection.
    @returns {boolean} - The success state of the operation.
    @throws {error} - The error encountered during the operation.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    let result = c.ConnectWithKey('localhost', 22, 'user', 'key');
    */
    ConnectWithKey(host, port, username, key) {
        // implemented in go
    };

    /**
    @method
    @description Run tries to open a new SSH session, then tries to execute the provided command in said session
    @param {string} cmd - The command to execute.
    @returns {string} - The output of the command.
    @throws {error} - The error encountered during the operation.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    let result = c.Run('ls');
    */
    Run(cmd) {
        // implemented in go
    };

    /**
    @method
    @description SetTimeout sets the timeout for the SSH connection in seconds
    @param {number} sec - The number of seconds for the timeout.
    @example
    let m = require('nuclei/ssh');
    let c = m.SSHClient();
    c.SetTimeout(30);
    */
    SetTimeout(sec) {
        // implemented in go
    };
};

module.exports = {
    SSHClient: SSHClient,
};