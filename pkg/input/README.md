## input

input package contains and provides loading, parsing , validating and normalizing of input data


## [transform](./transform.go)

Transform package transforms or normalizes the input data before it is sent to protocol executer this step mainly involves changes like adding default ports (if missing) , validating if input is file or directory or url and adjusting the input accordingly etc.


## Provider

Provider package contains the interface that every input format should implement for providing that input format to nuclei.

Currently Nuclei Supports three input providers:

1. SimpleInputProvider = A No-Op provider that takes a list of urls and implements the provider interface.

2. HttpInputProvider = A provider that supports loading and parsing input formats that contain complete Http Data like Entire Request, Response etc. Supported formats include Burp,openapi,swagger,postman,proxify etc.

3. ListInputProvider = Legacy/Default Provider that handles all list type inputs like urls,domains,ips,cidrs,files etc.


```go
func NewInputProvider(opts InputOptions) (InputProvider, error)
```

This function returns a InputProvider based by appropriately selecting input provider based on the input format (i.e either list or http) and returns the provider that can handle that input format.

