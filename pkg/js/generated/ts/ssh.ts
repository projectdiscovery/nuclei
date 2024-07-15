

/**
 * SSHClient is a client for SSH servers.
 * Internally client uses github.com/zmap/zgrab2/lib/ssh driver.
 * @example
 * ```javascript
 * const ssh = require('nuclei/ssh');
 * const client = new ssh.SSHClient();
 * ```
 */
export class SSHClient {
    

    // Constructor of SSHClient
    constructor() {}
    /**
    * SetTimeout sets the timeout for the SSH connection in seconds
    * @example
    * ```javascript
    * const ssh = require('nuclei/ssh');
    * const client = new ssh.SSHClient();
    * client.SetTimeout(10);
    * ```
    */
    public SetTimeout(sec: number): void {
        return;
    }
    

    /**
    * Connect tries to connect to provided host and port
    * with provided username and password with ssh.
    * Returns state of connection and error. If error is not nil,
    * state will be false
    * @example
    * ```javascript
    * const ssh = require('nuclei/ssh');
    * const client = new ssh.SSHClient();
    * const connected = client.Connect('acme.com', 22, 'username', 'password');
    * ```
    */
    public Connect(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * ConnectWithKey tries to connect to provided host and port
    * with provided username and private_key.
    * Returns state of connection and error. If error is not nil,
    * state will be false
    * @example
    * ```javascript
    * const ssh = require('nuclei/ssh');
    * const client = new ssh.SSHClient();
    * const privateKey = `-----BEGIN RSA PRIVATE KEY----- ...`;
    * const connected = client.ConnectWithKey('acme.com', 22, 'username', privateKey);
    * ```
    */
    public ConnectWithKey(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * ConnectSSHInfoMode tries to connect to provided host and port
    * with provided host and port
    * Returns HandshakeLog and error. If error is not nil,
    * state will be false
    * HandshakeLog is a struct that contains information about the
    * ssh connection
    * @example
    * ```javascript
    * const ssh = require('nuclei/ssh');
    * const client = new ssh.SSHClient();
    * const info = client.ConnectSSHInfoMode('acme.com', 22);
    * log(to_json(info));
    * ```
    */
    public ConnectSSHInfoMode(host: string, port: number): HandshakeLog | null | null {
        return null;
    }
    

    /**
    * Run tries to open a new SSH session, then tries to execute
    * the provided command in said session
    * Returns string and error. If error is not nil,
    * state will be false
    * The string contains the command output
    * @example
    * ```javascript
    * const ssh = require('nuclei/ssh');
    * const client = new ssh.SSHClient();
    * client.Connect('acme.com', 22, 'username', 'password');
    * const output = client.Run('id');
    * log(output);
    * ```
    */
    public Run(cmd: string): string | null {
        return null;
    }
    

    /**
    * Close closes the SSH connection and destroys the client
    * Returns the success state and error. If error is not nil,
    * state will be false
    * @example
    * ```javascript
    * const ssh = require('nuclei/ssh');
    * const client = new ssh.SSHClient();
    * client.Connect('acme.com', 22, 'username', 'password');
    * const closed = client.Close();
    * ```
    */
    public Close(): boolean | null {
        return null;
    }
    

}



/**
 * Algorithms Interface
 */
export interface Algorithms {
    
    Kex?: string,
    
    HostKey?: string,
    
    W?: DirectionAlgorithms,
    
    R?: DirectionAlgorithms,
}



/**
 * DirectionAlgorithms Interface
 */
export interface DirectionAlgorithms {
    
    Cipher?: string,
    
    MAC?: string,
    
    Compression?: string,
}



/**
 * EndpointId Interface
 */
export interface EndpointId {
    
    SoftwareVersion?: string,
    
    Comment?: string,
    
    Raw?: string,
    
    ProtoVersion?: string,
}



/**
 * HandshakeLog Interface
 */
export interface HandshakeLog {
    
    Banner?: string,
    
    UserAuth?: string[],
    
    ServerID?: EndpointId,
    
    ClientID?: EndpointId,
    
    ServerKex?: KexInitMsg,
    
    ClientKex?: KexInitMsg,
    
    AlgorithmSelection?: Algorithms,
}



/**
 * KexInitMsg Interface
 */
export interface KexInitMsg {
    
    KexAlgos?: string[],
    
    CiphersClientServer?: string[],
    
    MACsServerClient?: string[],
    
    LanguagesClientServer?: string[],
    
    CompressionClientServer?: string[],
    
    CompressionServerClient?: string[],
    
    Reserved?: number,
    
    MACsClientServer?: string[],
    
    /**
    * fixed size array of length: [16]
    */
    
    Cookie?: Uint8Array,
    
    ServerHostKeyAlgos?: string[],
    
    CiphersServerClient?: string[],
    
    LanguagesServerClient?: string[],
    
    FirstKexFollows?: boolean,
}

