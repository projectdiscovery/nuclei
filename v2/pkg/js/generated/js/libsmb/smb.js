// libsmb implements bindings for smb protocol in javascript
// to be used from nuclei scanner.

// Client is a client for SMB servers.
// 
// Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver.
// github.com/hirochachacha/go-smb2 driver
class Client {
    // ConnectSMBInfoMode tries to connect to provided host and port
    // and discovery SMB information
    // 
    // Returns handshake log and error. If error is not nil,
    // state will be false
    ConnectSMBInfoMode(host, port) {
        return SMBLog, error;
    };
    // DetectSMBGhost tries to detect SMBGhost vulnerability
    // by using SMBv3 compression feature.
    DetectSMBGhost(host, port) {
        return bool, error;
    };
    // ListSMBv2Metadata tries to connect to provided host and port
    // and list SMBv2 metadata.
    // 
    // Returns metadata and error. If error is not nil,
    // state will be false
    ListSMBv2Metadata(host, port) {
        return ServiceSMB, error;
    };
    // ListShares tries to connect to provided host and port
    // and list shares by using given credentials.
    // 
    // Credentials cannot be blank. guest or anonymous credentials
    // can be used by providing empty password.
    ListShares(host, port, user, password) {
        return [] string, error;
    };
};


module.exports = {
    Client: Client,
};