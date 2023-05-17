// libnet implements bindings for net protocol in javascript
// to be used from nuclei scanner.
function Close(conn) {

};

function Open(address) {

};

function OpenTLS(address) {

};

function Recv(conn, timeout) {

};

function Send(conn, data, timeout) {

};

function SendRecv(conn, data, timeout) {

};


module.exports = {
    Close: Close,
    Open: Open,
    OpenTLS: OpenTLS,
    Recv: Recv,
    Send: Send,
    SendRecv: SendRecv,
};