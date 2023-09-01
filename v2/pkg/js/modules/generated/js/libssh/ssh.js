// libssh implements bindings for ssh protocol in javascript
// to be used from nuclei scanner.

// Client is a client for SSH servers.
// 
// Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
class Client {
    // Connect tries to connect to provided host and port
    // with provided username and password with ssh.
    // 
    // Returns state of connection and error. If error is not nil,
    // state will be false
    Connect(host, port, username, password) {
        return bool, error;
    };
    // ConnectSSHInfoMode tries to connect to provided host and port
    // with provided host and port
    // 
    // Returns HandshakeLog and error. If error is not nil,
    // state will be false
    // 
    // HandshakeLog is a struct that contains information about the
    // ssh connection
    ConnectSSHInfoMode(host, port) {
        return HandshakeLog, error;
    };
    // ConnectWithKey tries to connect to provided host and port
    // with provided username and private_key.
    // 
    // Returns state of connection and error. If error is not nil,
    // state will be false
    ConnectWithKey(host, port, username, key) {
        return bool, error;
    };
};


module.exports = {
    Client: Client,
};