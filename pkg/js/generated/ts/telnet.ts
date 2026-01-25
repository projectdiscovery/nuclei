

/** Do */
export const DO = 253;

/** Don't */
export const DONT = 254;

/** Echo */
export const ECHO = 1;

/** Encryption option (0x26) */
export const ENCRYPT = 38;

/** Interpret As Command */
export const IAC = 255;

/** Negotiate About Window Size */
export const NAWS = 31;

/** Subnegotiation Begin */
export const SB = 250;

/** Subnegotiation End */
export const SE = 240;

/** Suppress Go Ahead */
export const SUPPRESS_GO_AHEAD = 3;

/** Terminal Type */
export const TERMINAL_TYPE = 24;

/** Will */
export const WILL = 251;

/** Won't */
export const WONT = 252;

/**
 * IsTelnet checks if a host is running a Telnet server.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const isTelnet = telnet.IsTelnet('acme.com', 23);
 * log(toJSON(isTelnet));
 * ```
 */
export function IsTelnet(ctx: any, host: string, port: number): IsTelnetResponse | null {
    return null;
}



/**
 * TelnetClient is a client for Telnet servers.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const client = new telnet.TelnetClient();
 * ```
 */
export class TelnetClient {
    

    // Constructor of TelnetClient
    constructor() {}
    /**
    * Connect tries to connect to provided host and port with telnet.
    * Optionally provides username and password for authentication.
    * Returns state of connection. If the connection is successful,
    * the function will return true, otherwise false.
    * @example
    * ```javascript
    * const telnet = require('nuclei/telnet');
    * const client = new telnet.TelnetClient();
    * const connected = client.Connect('acme.com', 23, 'username', 'password');
    * ```
    */
    public Connect(ctx: any, host: string, port: number, username: string, password: string): boolean | null {
        return null;
    }
    

    /**
    * Info gathers information about the telnet server including encryption support.
    * Uses the telnetmini library's DetectEncryption helper function.
    * WARNING: The connection used for detection becomes unusable after this call.
    * @example
    * ```javascript
    * const telnet = require('nuclei/telnet');
    * const client = new telnet.TelnetClient();
    * const info = client.Info('acme.com', 23);
    * log(toJSON(info));
    * ```
    */
    public Info(ctx: any, host: string, port: number): TelnetInfoResponse | null {
        return null;
    }
    

    /**
    * GetTelnetNTLMInfo implements the Nmap telnet-ntlm-info.nse script functionality.
    * This function uses the telnetmini library and SMB packet crafting functions to send
    * MS-TNAP NTLM authentication requests with null credentials. It might work only on
    * Microsoft Telnet servers.
    * @example
    * ```javascript
    * const telnet = require('nuclei/telnet');
    * const client = new telnet.TelnetClient();
    * const ntlmInfo = client.GetTelnetNTLMInfo('acme.com', 23);
    * log(toJSON(ntlmInfo));
    * ```
    */
    public GetTelnetNTLMInfo(ctx: any, host: string, port: number): NTLMInfoResponse | null | null {
        return null;
    }
    

}



/**
 * IsTelnetResponse is the response from the IsTelnet function.
 * this is returned by IsTelnet function.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const isTelnet = telnet.IsTelnet('acme.com', 23);
 * log(toJSON(isTelnet));
 * ```
 */
export interface IsTelnetResponse {
    
    IsTelnet?: boolean,
    
    Banner?: string,
}



/**
 * NTLMInfoResponse Interface
 */
export interface NTLMInfoResponse {
    
    DNSComputerName?: string,
    
    DNSTreeName?: string,
    
    ProductVersion?: string,
    
    Timestamp?: number,
    
    TargetName?: string,
    
    NetBIOSDomainName?: string,
    
    NetBIOSComputerName?: string,
    
    DNSDomainName?: string,
}



/**
 * TelnetInfoResponse is the response from the Info function.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const client = new telnet.TelnetClient();
 * const info = client.Info('acme.com', 23);
 * log(toJSON(info));
 * ```
 */
export interface TelnetInfoResponse {
    
    SupportsEncryption?: boolean,
    
    Banner?: string,
    
    Options?: Record<number, number[]>,
}

