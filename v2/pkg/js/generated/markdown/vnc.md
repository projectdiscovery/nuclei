## libvnc 
---


`libvnc` implements bindings for `vnc` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a minimal VNC client for nuclei scripts.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `IsVNC` |  IsVNC checks if a host is running a VNC server.  It returns a boolean indicating if the host is running a VNC server  and the banner of the VNC server. | `host`, `port` | `IsVNCResponse`, `error` |




## Exported Types Fields
### IsVNCResponse

| Name | Type | 
|--------|-------------|
| Banner | `string` |
| IsVNC | `bool` |
