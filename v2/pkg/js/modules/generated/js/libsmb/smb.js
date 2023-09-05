/**
 * @fileoverview This module implements bindings for smb protocol in javascript to be used from nuclei scanner.
 * Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver and github.com/hirochachacha/go-smb2 driver.
 */

/**
 * @class
 * @classdesc This class is a client for SMB servers.
 */
class Client {
    /**
     * @method
     * @description This method tries to connect to provided host and port and discover SMB information.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @returns {Object} Returns handshake log. If error occurs, state will be false.
     * @throws {Error} If an error occurs during the connection or discovery process.
     */
    ConnectSMBInfoMode(host, port) {
        // Code here...
    };

    /**
     * @method
     * @description This method tries to detect SMBGhost vulnerability by using SMBv3 compression feature.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @returns {boolean} Returns true if vulnerability is detected, false otherwise.
     * @throws {Error} If an error occurs during the detection process.
     */
    DetectSMBGhost(host, port) {
        // Code here...
    };

    /**
     * @method
     * @description This method tries to connect to provided host and port and list SMBv2 metadata.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @returns {Object} Returns metadata. If error occurs, state will be false.
     * @throws {Error} If an error occurs during the connection or listing process.
     */
    ListSMBv2Metadata(host, port) {
        // Code here...
    };

    /**
     * @method
     * @description This method tries to connect to provided host and port and list shares by using given credentials.
     * Credentials cannot be blank. guest or anonymous credentials can be used by providing empty password.
     * @param {string} host - The host to connect to.
     * @param {number} port - The port to connect to.
     * @param {string} user - The username for authentication.
     * @param {string} password - The password for authentication.
     * @returns {Array} Returns an array of shares.
     */
    ListShares(host, port, user, password) {
        // Code here...
    };
};

module.exports = {
    Client: Client,
};