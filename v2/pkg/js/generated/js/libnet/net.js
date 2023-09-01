// libnet implements bindings for net protocol in javascript
// to be used from nuclei scanner.

// Conn is a connection to a remote host.
class Conn {
    // Close closes the connection.
    Close() {
        return error;
    };
    // Recv receives data from the connection with a timeout.
    Recv(timeout, N) {
        return [] byte, error;
    };
    // Send sends data to the connection with a timeout.
    Send(data, timeout) {
        return error;
    };
    // SendRecv sends data to the connection and receives data from the connection with a timeout.
    SendRecv(data, timeout) {
        return [] byte, error;
    };
};

function Open(protocol, address) {

};

function OpenTLS(protocol, address) {

};


module.exports = {
    Conn: Conn,
    Open: Open,
    OpenTLS: OpenTLS,
};