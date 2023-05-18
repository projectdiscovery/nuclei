## librsync 
---


`librsync` implements bindings for `rsync` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a minimal Rsync client for nuclei scripts.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `IsRsync` |  IsRsync checks if a host is running a Rsync server. | `host`, `port` | `IsRsyncResponse`, `error` |




## Exported Types Fields
### IsRsyncResponse

| Name | Type | 
|--------|-------------|
| Banner | `string` |
| IsRsync | `bool` |
