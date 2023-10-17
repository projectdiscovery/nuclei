## jsdocgen

jsdocgen is LLM (OpenAI) based dev tool it takes generated javascript files and annotes them with jsdoc comments using predefined prompt

### Usage

```bash
 ./jsdocgen -h
Usage of ./jsdocgen:
  -dir string
    	directory to process
  -key string
    	openai api key
  -keyfile string
    	openai api key file
```

### Example

```bash
./jsdocgen -dir modules/generated/js/libmysql -keyfile ~/.openai/key
```


### Example Conversion

when `bindgen` is executed it generates basic javascript (which currently is incorrect) and looks like this but the idea is to generate bare minimum that LLM has idea what we are trying to do

```javascript
/**@module rdp */
// rdp implements bindings for rdp protocol in javascript
// to be used from nuclei scanner.

// RDPClient is a client for rdp servers
class RDPClient {
    // CheckRDPAuth checks if the given host and port are running rdp server
    // with authentication and returns their metadata.
    CheckRDPAuth(host, port) {
        return CheckRDPAuthResponse, error;
    };
    // IsRDP checks if the given host and port are running rdp server.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    // 
    // The Name of the OS is also returned if the connection is successful.
    IsRDP(host, port) {
        return IsRDPResponse, error;
    };
};


module.exports = {
    RDPClient: RDPClient,
};
```

And when `jsdocgen` is executed it generates the following output

```javascript
/**
 * @module rdp
 * This module implements bindings for rdp protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc RDPClient is a client for rdp servers
 */
class RDPClient {
    /**
     * @method
     * @name CheckRDPAuth
     * @description checks if the given host and port are running rdp server with authentication and returns their metadata.
     * @param {string} host - The host of the rdp server
     * @param {number} port - The port of the rdp server
     * @returns {CheckRDPAuthResponse} - The response from the rdp server
     * @throws {error} If there is an error in the request
     * @example
     * let client = new RDPClient();
     * client.CheckRDPAuth("localhost", 3389);
     */
    CheckRDPAuth(host, port) {
        // implemented in go
    };

    /**
     * @method
     * @name IsRDP
     * @description checks if the given host and port are running rdp server.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The Name of the OS is also returned if the connection is successful.
     * @param {string} host - The host of the rdp server
     * @param {number} port - The port of the rdp server
     * @returns {IsRDPResponse} - The response from the rdp server
     * @throws {error} If there is an error in the request
     * @example
     * let client = new RDPClient();
     * client.IsRDP("localhost", 3389);
     */
    IsRDP(host, port) {
        // implemented in go
    };
};

module.exports = {
    RDPClient: RDPClient,
};
```

Now we can see the output is much more readable and make sense.

## Note:

jsdocgen is not perfect and it is not supposed to be, it is intended to **almost** automate boooring stuff but will always require some manual intervention to make it perfect.