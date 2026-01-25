


export const EncryptionLevelFIPS140_1 = "FIPS140_1";


export const EncryptionLevelRC4_128bit = "RC4_128bit";


export const EncryptionLevelRC4_40bit = "RC4_40bit";


export const EncryptionLevelRC4_56bit = "RC4_56bit";


export const SecurityLayerCredSSP = "CredSSP";


export const SecurityLayerCredSSPWithEarlyUserAuth = "CredSSPWithEarlyUserAuth";


export const SecurityLayerNativeRDP = "NativeRDP";


export const SecurityLayerRDSTLS = "RDSTLS";


export const SecurityLayerSSL = "SSL";

/**
 * CheckRDPAuth checks if the given host and port are running rdp server
 * with authentication and returns their metadata.
 * If connection is successful, it returns true.
 * @example
 * ```javascript
 * const rdp = require('nuclei/rdp');
 * const checkRDPAuth = rdp.CheckRDPAuth('acme.com', 3389);
 * log(toJSON(checkRDPAuth));
 * ```
 */
export function CheckRDPAuth(ctx: any, host: string, port: number): CheckRDPAuthResponse | null {
    return null;
}



/**
 * CheckRDPEncryption checks the RDP server's supported security layers and encryption levels.
 * It tests different protocols and ciphers to determine what is supported.
 * @example
 * ```javascript
 * const rdp = require('nuclei/rdp');
 * const encryption = rdp.CheckRDPEncryption('acme.com', 3389);
 * log(toJSON(encryption));
 * ```
 */
export function CheckRDPEncryption(ctx: any, host: string, port: number): RDPEncryptionResponse | null {
    return null;
}



/**
 * IsRDP checks if the given host and port are running rdp server.
 * If connection is successful, it returns true.
 * If connection is unsuccessful, it returns false and error.
 * The Name of the OS is also returned if the connection is successful.
 * @example
 * ```javascript
 * const rdp = require('nuclei/rdp');
 * const isRDP = rdp.IsRDP('acme.com', 3389);
 * log(toJSON(isRDP));
 * ```
 */
export function IsRDP(ctx: any, host: string, port: number): IsRDPResponse | null {
    return null;
}



/**
 * CheckRDPAuthResponse is the response from the CheckRDPAuth function.
 * this is returned by CheckRDPAuth function.
 * @example
 * ```javascript
 * const rdp = require('nuclei/rdp');
 * const checkRDPAuth = rdp.CheckRDPAuth('acme.com', 3389);
 * log(toJSON(checkRDPAuth));
 * ```
 */
export interface CheckRDPAuthResponse {
    
    PluginInfo?: ServiceRDP,
    
    Auth?: boolean,
}



/**
 * IsRDPResponse is the response from the IsRDP function.
 * this is returned by IsRDP function.
 * @example
 * ```javascript
 * const rdp = require('nuclei/rdp');
 * const isRDP = rdp.IsRDP('acme.com', 3389);
 * log(toJSON(isRDP));
 * ```
 */
export interface IsRDPResponse {
    
    IsRDP?: boolean,
    
    OS?: string,
}



/**
 * RDPEncryptionResponse is the response from the CheckRDPEncryption function.
 * This is returned by CheckRDPEncryption function.
 * @example
 * ```javascript
 * const rdp = require('nuclei/rdp');
 * const encryption = rdp.CheckRDPEncryption('acme.com', 3389);
 * log(toJSON(encryption));
 * ```
 */
export interface RDPEncryptionResponse {
    
    /**
    * Protocols
    */
    
    NativeRDP?: boolean,
    
    SSL?: boolean,
    
    CredSSP?: boolean,
    
    RDSTLS?: boolean,
    
    CredSSPWithEarlyUserAuth?: boolean,
    
    /**
    * EncryptionLevels
    */
    
    RC4_40bit?: boolean,
    
    RC4_56bit?: boolean,
    
    RC4_128bit?: boolean,
    
    FIPS140_1?: boolean,
}



/**
 * ServiceRDP Interface
 */
export interface ServiceRDP {
    
    TargetName?: string,
    
    NetBIOSComputerName?: string,
    
    NetBIOSDomainName?: string,
    
    DNSComputerName?: string,
    
    DNSDomainName?: string,
    
    ForestName?: string,
    
    OSFingerprint?: string,
    
    OSVersion?: string,
}

