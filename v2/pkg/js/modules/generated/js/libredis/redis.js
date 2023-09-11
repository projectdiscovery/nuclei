/** 
 * @module redis 
 */

/**
 * Connect to a Redis server.
 * @function
 * @param {string} host - The host of the Redis server.
 * @param {number} port - The port of the Redis server.
 * @param {string} password - The password for the Redis server.
 */
function Connect(host, port, password) {
    // implemented in go
};

/**
 * Get information about the Redis server.
 * @function
 * @param {string} host - The host of the Redis server.
 * @param {number} port - The port of the Redis server.
 * @returns {Object} An object containing information about the server.
 */
function GetServerInfo(host, port) {
    // implemented in go
};

/**
 * Get information about the Redis server with authentication.
 * @function
 * @param {string} host - The host of the Redis server.
 * @param {number} port - The port of the Redis server.
 * @param {string} password - The password for the Redis server.
 * @returns {Object} An object containing information about the server.
 */
function GetServerInfoAuth(host, port, password) {
    // implemented in go
};

/**
 * Check if the Redis server is authenticated.
 * @function
 * @param {string} host - The host of the Redis server.
 * @param {number} port - The port of the Redis server.
 * @returns {boolean} True if the server is authenticated, false otherwise.
 */
function IsAuthenticated(host, port) {
    // implemented in go
};

/**
 * Run a Lua script on the Redis server.
 * @function
 * @param {string} host - The host of the Redis server.
 * @param {number} port - The port of the Redis server.
 * @param {string} password - The password for the Redis server.
 * @param {string} script - The Lua script to run.
 * @returns {Object} The result of the script execution.
 */
function RunLuaScript(host, port, password, script) {
    // implemented in go
};

// ReadOnly DONOT EDIT
module.exports = {
    Connect: Connect,
    GetServerInfo: GetServerInfo,
    GetServerInfoAuth: GetServerInfoAuth,
    IsAuthenticated: IsAuthenticated,
    RunLuaScript: RunLuaScript,
};