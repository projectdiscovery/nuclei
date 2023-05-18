## libnet 
---


`libnet` implements bindings for `net` protocol in javascript
to be used from nuclei scanner.





## Exported Functions

| Name | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
Close |  Close closes the connection. | `conn` | `error` |
Open |  Open opens a new connection to the address with a timeout. | `address` | `error` |
OpenTLS |  Open opens a new connection to the address with a timeout. | `address` | `error` |
Recv |  Recv receives data from the connection with a timeout. | `conn`, `timeout` | `[byte]`, `error` |
Send |  Send sends data to the connection with a timeout. | `conn`, `data`, `timeout` | `error` |
SendRecv |  SendRecv sends data to the connection and receives data from the connection with a timeout. | `conn`, `data`, `timeout` | `[byte]`, `error` |


