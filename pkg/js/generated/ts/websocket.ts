

/**
 * Client is a WebSocket client for nuclei JS templates.
 * @example
 * ```javascript
 * const websocket = require('nuclei/websocket');
 * const client = new websocket.Client('ws://acme.com/socket');
 * client.Send('hello');
 * const reply = client.Receive();
 * client.Close();
 * ```
 */
export class Client {


    public URL?: string;


    public Protocol?: string;


    /**
    * ResponseHeaders are the handshake response headers, set after connecting.
    * Upgrade, Connection and Sec-WebSocket-* headers are validated by the
    * handshake and not included; Protocol holds the negotiated subprotocol.
    */
    public ResponseHeaders?: Record<string, string>;


    // Constructor of Client
    constructor(url: string, options?: Options) {}
    /**
    * Connect performs the opening handshake. It is optional; Send and Receive
    * connect on demand.
    * @example
    * ```javascript
    * const websocket = require('nuclei/websocket');
    * const client = new websocket.Client('ws://acme.com/socket');
    * client.Connect();
    * log(client.Protocol);
    * ```
    */
    public Connect(): void {
        return;
    }


    /**
    * Send sends a text message.
    * @example
    * ```javascript
    * const websocket = require('nuclei/websocket');
    * const client = new websocket.Client('ws://acme.com/socket');
    * client.Send('hello');
    * ```
    */
    public Send(data: string): void {
        return;
    }


    /**
    * SendHex sends a binary message given as hex.
    * @example
    * ```javascript
    * const websocket = require('nuclei/websocket');
    * const client = new websocket.Client('ws://acme.com/socket');
    * client.SendHex('68656c6c6f');
    * ```
    */
    public SendHex(data: string): void {
        return;
    }


    /**
    * Receive returns the next text or binary message as a string. Pings are
    * answered automatically.
    * @example
    * ```javascript
    * const websocket = require('nuclei/websocket');
    * const client = new websocket.Client('ws://acme.com/socket');
    * const message = client.Receive();
    * ```
    */
    public Receive(): string | null {
        return null;
    }


    /**
    * ReceiveHex returns the next text or binary message as hex.
    * @example
    * ```javascript
    * const websocket = require('nuclei/websocket');
    * const client = new websocket.Client('ws://acme.com/socket');
    * const message = client.ReceiveHex();
    * ```
    */
    public ReceiveHex(): string | null {
        return null;
    }


    /**
    * Close sends a close frame and closes the connection.
    * @example
    * ```javascript
    * const websocket = require('nuclei/websocket');
    * const client = new websocket.Client('ws://acme.com/socket');
    * client.Close();
    * ```
    */
    public Close(): void {
        return;
    }


}



/**
 * Options configures a WebSocket Client. All fields are optional.
 * @example
 * ```javascript
 * const websocket = require('nuclei/websocket');
 * const opts = new websocket.Options();
 * opts.Headers = {'Origin': 'https://acme.com'};
 * opts.Protocols = ['chat'];
 * const client = new websocket.Client('wss://acme.com/socket', opts);
 * ```
 */
export interface Options {

    Headers?: Record<string, string>,

    Protocols?: string[],

    TimeoutSeconds?: number,

    ServerName?: string,
}

