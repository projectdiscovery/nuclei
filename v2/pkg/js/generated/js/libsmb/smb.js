/** 
 * @module smb
 */

/**
 * @class
 * @description SMBClient is a client for SMB servers. Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver and github.com/hirochachacha/go-smb2 driver.
 */
class SMBClient {
    /**
     * @method
     * @description ConnectSMBInfoMode tries to connect to provided host and port and discovery SMB information
     * @param {string} host - The host to connect to
     * @param {number} port - The port to connect to
     * @returns {Object} SMBLog - The handshake log
     * @throws {Error} If an error occurs, the error is thrown
     * @example
     * let client = new SMBClient();
     * try {
     *     let log = client.ConnectSMBInfoMode('localhost', 8080);
     * } catch (error) {
     *     console.error(error);
     * }
     */
    ConnectSMBInfoMode(host, port) {
        // implemented in go
    };

    /**
     * @method
     * @description DetectSMBGhost tries to detect SMBGhost vulnerability by using SMBv3 compression feature.
     * @param {string} host - The host to connect to
     * @param {number} port - The port to connect to
     * @returns {boolean} - Returns true if vulnerability is detected, false otherwise
     * @throws {Error} If an error occurs, the error is thrown
     * @example
     * let client = new SMBClient();
     * try {
     *     let isVulnerable = client.DetectSMBGhost('localhost', 8080);
     * } catch (error) {
     *     console.error(error);
     * }
     */
    DetectSMBGhost(host, port) {
        // implemented in go
    };

    /**
     * @method
     * @description ListSMBv2Metadata tries to connect to provided host and port and list SMBv2 metadata.
     * @param {string} host - The host to connect to
     * @param {number} port - The port to connect to
     * @returns {Object} ServiceSMB - The metadata
     * @throws {Error} If an error occurs, the error is thrown
     * @example
     * let client = new SMBClient();
     * try {
     *     let metadata = client.ListSMBv2Metadata('localhost', 8080);
     * } catch (error) {
     *     console.error(error);
     * }
     */
    ListSMBv2Metadata(host, port) {
        // implemented in go
    };

    /**
     * @method
     * @description ListShares tries to connect to provided host and port and list shares by using given credentials. Credentials cannot be blank. guest or anonymous credentials can be used by providing empty password.
     * @param {string} host - The host to connect to
     * @param {number} port - The port to connect to
     * @param {string} user - The username
     * @param {string} password - The password
     * @returns {Array.<string>} - The list of shares
     * @throws {Error} If an error occurs, the error is thrown
     * @example
     * let client = new SMBClient();
     * try {
     *     let shares = client.ListShares('localhost', 8080, 'user', 'password');
     * } catch (error) {
     *     console.error(error);
     * }
     */
    ListShares(host, port, user, password) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    SMBClient: SMBClient,
};