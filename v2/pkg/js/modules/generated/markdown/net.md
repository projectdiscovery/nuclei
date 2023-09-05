## net 
---


`net` implements bindings for `net` protocol in javascript
to be used from nuclei scanner.



## Types

### Conn

 Conn is a connection to a remote host.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `Close` |  Close closes the connection. |  | `error` |
| `Recv` |  Recv receives data from the connection with a timeout. | `timeout`, `N` | `[]byte`, `error` |
| `Send` |  Send sends data to the connection with a timeout. | `data`, `timeout` | `error` |
| `SendRecv` |  SendRecv sends data to the connection and receives data from the connection with a timeout. | `data`, `timeout` | `[]byte`, `error` |


## Exported Functions

| Name | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
Open |  Open opens a new connection to the address with a timeout. | `protocol`, `address` | `Conn`, `error` |
OpenTLS |  Open opens a new connection to the address with a timeout. | `protocol`, `address` | `Conn`, `error` |


## Exported Types Fields
### Conn

| Name | Type | 
|--------|-------------|
| conn | `net.Conn` |




