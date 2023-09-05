// libredis implements bindings for redis protocol in javascript
// to be used from nuclei scanner.
function Connect(host, port, password) {

};

function GetServerInfo(host, port) {

};

function GetServerInfoAuth(host, port, password) {

};

function IsAuthenticated(host, port) {

};

function RunLuaScript(host, port, password, script) {

};


module.exports = {
    Connect: Connect,
    GetServerInfo: GetServerInfo,
    GetServerInfoAuth: GetServerInfoAuth,
    IsAuthenticated: IsAuthenticated,
    RunLuaScript: RunLuaScript,
};