## smb 
---


`smb` implements bindings for `smb` protocol in javascript
to be used from nuclei scanner.



## Types

### SMBClient

 SMBClient is a client for SMB servers.    Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver.  github.com/hirochachacha/go-smb2 driver

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `ConnectSMBInfoMode` |  ConnectSMBInfoMode tries to connect to provided host and port  and discovery SMB information    Returns handshake log and error. If error is not nil,  state will be false | `host`, `port` | `SMBLog`, `error` |
| `DetectSMBGhost` |  DetectSMBGhost tries to detect SMBGhost vulnerability  by using SMBv3 compression feature. | `host`, `port` | `bool`, `error` |
| `ListSMBv2Metadata` |  ListSMBv2Metadata tries to connect to provided host and port  and list SMBv2 metadata.    Returns metadata and error. If error is not nil,  state will be false | `host`, `port` | `ServiceSMB`, `error` |
| `ListShares` |  ListShares tries to connect to provided host and port  and list shares by using given credentials.    Credentials cannot be blank. guest or anonymous credentials  can be used by providing empty password. | `host`, `port`, `user`, `password` | `[]string`, `error` |




## Exported Types Fields
### HeaderLog

| Name | Type | 
|--------|-------------|
| Command | `uint16` |
| Credits | `uint16` |
| Flags | `uint32` |
| ProtocolID | `[]byte` |
| Status | `uint32` |
### NegotiationLog

| Name | Type | 
|--------|-------------|
| AuthenticationTypes | `[]string` |
| Capabilities | `uint32` |
| DialectRevision | `uint16` |
| HeaderLog | `HeaderLog` |
| SecurityMode | `uint16` |
| ServerGuid | `[]byte` |
| ServerStartTime | `uint32` |
| SystemTime | `uint32` |
### SMBCapabilities

| Name | Type | 
|--------|-------------|
| DFSSupport | `bool` |
| DirLeasing | `bool` |
| Encryption | `bool` |
| LargeMTU | `bool` |
| Leasing | `bool` |
| MultiChan | `bool` |
| Persist | `bool` |
### SMBLog

| Name | Type | 
|--------|-------------|
| Capabilities | `Capabilities` |
| GroupName | `string` |
| HasNTLM | `bool` |
| NTLM | `string` |
| NativeOs | `string` |
| NegotiationLog | `NegotiationLog` |
| SessionSetupLog | `SessionSetupLog` |
| SupportV1 | `bool` |
| Version | `Version` |
### SMBVersions

| Name | Type | 
|--------|-------------|
| Major | `uint8` |
| Minor | `uint8` |
| Revision | `uint8` |
| VerString | `string` |
### ServiceSMB

| Name | Type | 
|--------|-------------|
| DNSComputerName | `string` |
| DNSDomainName | `string` |
| ForestName | `string` |
| NetBIOSComputerName | `string` |
| NetBIOSDomainName | `string` |
| OSVersion | `string` |
| SigningEnabled | `bool` |
| SigningRequired | `bool` |
### SessionSetupLog

| Name | Type | 
|--------|-------------|
| HeaderLog | `HeaderLog` |
| NegotiateFlags | `uint32` |
| SetupFlags | `uint16` |
| TargetName | `string` |




