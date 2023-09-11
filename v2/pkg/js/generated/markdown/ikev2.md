## ikev2 
---


`ikev2` implements bindings for `ikev2` protocol in javascript
to be used from nuclei scanner.



## Types

### IKEMessage

 IKEMessage is the IKEv2 message    IKEv2 implements a limited subset of IKEv2 Protocol, specifically  the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `AppendPayload` |  AppendPayload appends a payload to the IKE message | `payload` |  |
| `Encode` |  Encode encodes the final IKE message |  | `[]byte`, `error` |




## Exported Types Fields
### IKEMessage

| Name | Type | 
|--------|-------------|
| ExchangeType | `uint8` |
| Flags | `uint8` |
| InitiatorSPI | `uint64` |
| Payloads | `[]IKEPayload` |
| Version | `uint8` |
### IKENonce

| Name | Type | 
|--------|-------------|
| NonceData | `[]byte` |
### IKENotification

| Name | Type | 
|--------|-------------|
| NotificationData | `[]byte` |
| NotifyMessageType | `uint16` |



## Exported Variables Values

| Name | Value |
|--------|-------------|
| IKE_EXCHANGE_AUTH | `35` |
| IKE_EXCHANGE_CREATE_CHILD_SA | `36` |
| IKE_EXCHANGE_INFORMATIONAL | `37` |
| IKE_EXCHANGE_SA_INIT | `34` |
| IKE_FLAGS_InitiatorBitCheck | `0x08` |
| IKE_NOTIFY_NO_PROPOSAL_CHOSEN | `14` |
| IKE_NOTIFY_USE_TRANSPORT_MODE | `16391` |
| IKE_VERSION_2 | `0x20` |


## Exported Interfaces
### IKEPayload

 IKEPayload is the IKEv2 payload interface    All the payloads like IKENotification, IKENonce, etc. implement  this interface.
