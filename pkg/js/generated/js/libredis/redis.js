/** @module redis */

/**
 * @function
 * @description Connect tries to connect redis server with password
 * @param {string} host - The host of the redis server.
 * @param {number} port - The port of the redis server.
 * @param {string} password - The password for the redis server.
 * @returns {boolean} - The status of the connection.
 * @throws {error} - The error encountered during connection.
 * @example
 * let m = require('nuclei/redis'); 
 * let status = m.Connect('localhost', 6379, 'password');
 */
function Connect(host, port, password) {
    // implemented in go
};

/**
 * @function
 * @description GetServerInfo returns the server info for a redis server
 * @param {string} host - The host of the redis server.
 * @param {number} port - The port of the redis server.
 * @returns {string} - The server info.
 * @throws {error} - The error encountered during getting server info.
 * @example
 * let m = require('nuclei/redis'); 
 * let info = m.GetServerInfo('localhost', 6379);
 */
function GetServerInfo(host, port) {
    // implemented in go
};

/**
 * @function
 * @description GetServerInfoAuth returns the server info for a redis server
 * @param {string} host - The host of the redis server.
 * @param {number} port - The port of the redis server.
 * @param {string} password - The password for the redis server.
 * @returns {string} - The server info.
 * @throws {error} - The error encountered during getting server info.
 * @example
 * let m = require('nuclei/redis'); 
 * let info = m.GetServerInfoAuth('localhost', 6379, 'password');
 */
function GetServerInfoAuth(host, port, password) {
    // implemented in go
};

/**
 * @function
 * @description IsAuthenticated checks if the redis server requires authentication
 * @param {string} host - The host of the redis server.
 * @param {number} port - The port of the redis server.
 * @returns {boolean} - The authentication status.
 * @throws {error} - The error encountered during checking authentication.
 * @example
 * let m = require('nuclei/redis'); 
 * let isAuthenticated = m.IsAuthenticated('localhost', 6379);
 */
function IsAuthenticated(host, port) {
    // implemented in go
};

/**
 * @function
 * @description RunLuaScript runs a lua script on the redis server
 * @param {string} host - The host of the redis server.
 * @param {number} port - The port of the redis server.
 * @param {string} password - The password for the redis server.
 * @param {string} script - The lua script to run.
 * @throws {error} - The error encountered during running the lua script.
 * @example
 * let m = require('nuclei/redis'); 
 * m.RunLuaScript('localhost', 6379, 'password', 'return redis.call(\'ping\')');
 */
function RunLuaScript(host, port, password, script) {
    // implemented in go
};

module.exports = {
    Connect: Connect,
    GetServerInfo: GetServerInfo,
    GetServerInfoAuth: GetServerInfoAuth,
    IsAuthenticated: IsAuthenticated,
    RunLuaScript: RunLuaScript,
};