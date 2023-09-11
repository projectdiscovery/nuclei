## ssh 
---


`ssh` implements bindings for `ssh` protocol in javascript
to be used from nuclei scanner.



## Types

### SSHClient

 SSHClient is a client for SSH servers.    Internally client uses github.com/zmap/zgrab2/lib/ssh driver.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `Connect` |  Connect tries to connect to provided host and port  with provided username and password with ssh.    Returns state of connection and error. If error is not nil,  state will be false | `host`, `port`, `username`, `password` | `bool`, `error` |
| `ConnectSSHInfoMode` |  ConnectSSHInfoMode tries to connect to provided host and port  with provided host and port    Returns HandshakeLog and error. If error is not nil,  state will be false    HandshakeLog is a struct that contains information about the  ssh connection | `host`, `port` | `HandshakeLog`, `error` |
| `ConnectWithKey` |  ConnectWithKey tries to connect to provided host and port  with provided username and private_key.    Returns state of connection and error. If error is not nil,  state will be false | `host`, `port`, `username`, `key` | `bool`, `error` |




## Exported Types Fields
### Algorithms

| Name | Type | 
|--------|-------------|
| HostKey | `string` |
| Kex | `string` |
| R | `R` |
| W | `W` |
### EndpointId

| Name | Type | 
|--------|-------------|
| Comment | `string` |
| ProtoVersion | `string` |
| Raw | `string` |
| SoftwareVersion | `string` |
### HandshakeLog

| Name | Type | 
|--------|-------------|
| AlgorithmSelection | `AlgorithmSelection` |
| Banner | `string` |
| ClientID | `ClientID` |
| ClientKex | `ClientKex` |
| Crypto | `Crypto` |
| DHKeyExchange | `github.com/zmap/zgrab2/lib/ssh.kexAlgorithm` |
| ServerID | `ServerID` |
| ServerKex | `ServerKex` |
| UserAuth | `[]string` |
### KexInitMsg

| Name | Type | 
|--------|-------------|
| CiphersClientServer | `[]string` |
| CiphersServerClient | `[]string` |
| CompressionClientServer | `[]string` |
| CompressionServerClient | `[]string` |
| Cookie | `[16]byte` |
| FirstKexFollows | `bool` |
| KexAlgos | `[]string` |
| LanguagesClientServer | `[]string` |
| LanguagesServerClient | `[]string` |
| MACsClientServer | `[]string` |
| MACsServerClient | `[]string` |
| Reserved | `uint32` |
| ServerHostKeyAlgos | `[]string` |




