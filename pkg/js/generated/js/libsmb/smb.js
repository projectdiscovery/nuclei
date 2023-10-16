/** @module smb */

/**
 * @typedef {object} SMBLog
 * @description SMBLog is an object containing the log of the SMB handshake.
 */
const SMBLog = {};

/**
 * @typedef {object} ServiceSMB
 * @description ServiceSMB is an object containing the metadata of the SMBv2 service.
 */

const ServiceSMB = {};

/**
 * @class
 * @classdesc SMBClient is a client for SMB servers.
 */
class SMBClient {
    /**
    * @method
    * @description ConnectSMBInfoMode tries to connect to provided host and port and discover SMB information
    * @param {string} host - The host to connect to.
    * @param {string} port - The port to connect to.
    * @returns {SMBLog} - The log of the SMB handshake.
    * @throws {error} - The error encountered during the connection.
    * @example
    * let m = require('nuclei/smb');
    * let c = m.SMBClient();
    * let log = c.ConnectSMBInfoMode('localhost', '445');
    */
    ConnectSMBInfoMode(host, port) {
        // implemented in go
    };

    /**
    * @method
    * @description DetectSMBGhost tries to detect SMBGhost vulnerability by using SMBv3 compression feature.
    * @param {string} host - The host to connect to.
    * @param {string} port - The port to connect to.
    * @returns {boolean} - The result of the SMBGhost vulnerability detection.
    * @throws {error} - The error encountered during the detection.
    * @example
    * let m = require('nuclei/smb');
    * let c = m.SMBClient();
    * let isVulnerable = c.DetectSMBGhost('localhost', '445');
    */
    DetectSMBGhost(host, port) {
        // implemented in go
    };

    /**
    * @method
    * @description ListSMBv2Metadata tries to connect to provided host and port and list SMBv2 metadata.
    * @param {string} host - The host to connect to.
    * @param {string} port - The port to connect to.
    * @returns {ServiceSMB} - The metadata of the SMBv2 service.
    * @throws {error} - The error encountered during the listing.
    * @example
    * let m = require('nuclei/smb');
    * let c = m.SMBClient();
    * let metadata = c.ListSMBv2Metadata('localhost', '445');
    */
    ListSMBv2Metadata(host, port) {
        // implemented in go
    };

    /**
    * @method
    * @description ListShares tries to connect to provided host and port and list shares by using given credentials.
    * @param {string} host - The host to connect to.
    * @param {string} port - The port to connect to.
    * @param {string} user - The username for authentication.
    * @param {string} password - The password for authentication.
    * @returns {string[]} - The list of shares.
    * @throws {error} - The error encountered during the listing.
    * @example
    * let m = require('nuclei/smb');
    * let c = m.SMBClient();
    * let shares = c.ListShares('localhost', '445', 'user', 'password');
    */
    ListShares(host, port, user, password) {
        // implemented in go
    };
};

module.exports = {
    SMBClient: SMBClient,
};