## libssh 
---


`libssh` implements bindings for `ssh` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a client for SSH servers.    Internally client uses github.com/zmap/zgrab2/lib/ssh driver.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `Connect` |  Connect tries to connect to provided host and port  with provided username and password with ssh.    Returns state of connection and error. If error is not nil,  state will be false | host, port, username, password | bool, error |
| `ConnectSSHInfoMode` |  ConnectSSHInfoMode tries to connect to provided host and port  with provided host and port    Returns HandshakeLog and error. If error is not nil,  state will be false    HandshakeLog is a struct that contains information about the  ssh connection | host, port | HandshakeLog, error |
| `ConnectWithKey` |  ConnectWithKey tries to connect to provided host and port  with provided username and private_key.    Returns state of connection and error. If error is not nil,  state will be false | host, port, username, key | bool, error |

