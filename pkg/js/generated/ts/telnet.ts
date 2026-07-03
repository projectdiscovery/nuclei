

/**
 * IsTelnet checks if a host is running a Telnet server.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const isTelnet = telnet.IsTelnet('acme.com', 23);
 * log(toJSON(isTelnet));
 * ```
 */
export function IsTelnet(host: string, port: number): IsTelnetResponse | null {
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
    public Connect(host: string, port: number, username: string, password: string): boolean {
        return false;
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
    public Info(host: string, port: number): TelnetInfoResponse | null {
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
    public GetTelnetNTLMInfo(host: string, port: number): NTLMInfoResponse | null {
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
    
    Options?: { [key: number]: number[] },
}

/**
 * NTLMInfoResponse represents the response from NTLM information gathering.
 * This matches exactly the output structure from the Nmap telnet-ntlm-info.nse script.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const client = new telnet.TelnetClient();
 * const ntlmInfo = client.GetTelnetNTLMInfo('acme.com', 23);
 * log(toJSON(ntlmInfo));
 * ```
 */
export interface NTLMInfoResponse {
    
    /**
     * Target_Name from script (target_realm in script)
     */
    TargetName?: string,
    
    /**
     * NetBIOS_Domain_Name from script
     */
    NetBIOSDomainName?: string,
    
    /**
     * NetBIOS_Computer_Name from script
     */
    NetBIOSComputerName?: string,
    
    /**
     * DNS_Domain_Name from script
     */
    DNSDomainName?: string,
    
    /**
     * DNS_Computer_Name from script (fqdn in script)
     */
    DNSComputerName?: string,
    
    /**
     * DNS_Tree_Name from script (dns_forest_name in script)
     */
    DNSTreeName?: string,
    
    /**
     * Product_Version from script
     */
    ProductVersion?: string,
    
    /**
     * Raw timestamp for skew calculation
     */
    Timestamp?: number,
}

