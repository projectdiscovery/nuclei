// librdp implements bindings for rdp protocol in javascript
// to be used from nuclei scanner.

// Client is a client for rdp servers
class Client {
    // CheckRDPAuth checks if the given host and port are running rdp server
    // with authentication and returns their metadata.
    CheckRDPAuth(host, port) {
        return CheckRDPAuthResponse, error;
    };
    // IsRDP checks if the given host and port are running rdp server.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    // 
    // The Name of the OS is also returned if the connection is successful.
    IsRDP(host, port) {
        return IsRDPResponse, error;
    };
};


module.exports = {
    Client: Client,
};