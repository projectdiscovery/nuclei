## libsmb 
---


`libsmb` implements bindings for `smb` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a client for SMB servers.    Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver.  github.com/hirochachacha/go-smb2 driver

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `ConnectSMBInfoMode` |  ConnectSMBInfoMode tries to connect to provided host and port  and discovery SMB information    Returns handshake log and error. If error is not nil,  state will be false | host, port | SMBLog, error |
| `ListSMBv2Metadata` |  ListSMBv2Metadata tries to connect to provided host and port  and list SMBv2 metadata.    Returns metadata and error. If error is not nil,  state will be false | host, port | ServiceSMB, error |
| `ListShares` |  ListShares tries to connect to provided host and port  and list shares by using given credentials.    Credentials cannot be blank. guest or anonymous credentials  can be used by providing empty password. | host, port, user, password | [string], error |




