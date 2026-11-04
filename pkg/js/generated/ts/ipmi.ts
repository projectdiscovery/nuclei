

/**
 * CheckRAKPPassword reports whether password produced hash. It runs offline,
 * so it can test any number of passwords without touching the BMC.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const hash = ipmi.GetRAKPHash('acme.com', 623, 'ADMIN');
 * log(ipmi.CheckRAKPPassword(hash, 'ADMIN'));
 * ```
 */
export function CheckRAKPPassword(hash: RAKPHash, password: string): boolean {
    return false;
}



/**
 * FindRAKPPassword returns the first of passwords that produced hash, or an
 * empty string.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const hash = ipmi.GetRAKPHash('acme.com', 623, 'root');
 * log(ipmi.FindRAKPPassword(hash, ['calvin', 'root', 'admin']));
 * ```
 */
export function FindRAKPPassword(hash: RAKPHash, passwords: string[]): string {
    return "";
}



/**
 * GetAuthCapabilities returns the authentication capabilities the BMC
 * advertises on the current channel.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const caps = ipmi.GetAuthCapabilities('acme.com', 623);
 * log(caps.AnonymousLogin);
 * ```
 */
export function GetAuthCapabilities(ctx: any, host: string, port: number): AuthCapabilities | null {
    return null;
}



/**
 * GetCipherSuites returns the IDs of the RMCP+ cipher suites the BMC
 * offers. Cipher suite 0 authenticates nothing, so any password logs in.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const suites = ipmi.GetCipherSuites('acme.com', 623);
 * log(suites.includes(0));
 * ```
 */
export function GetCipherSuites(ctx: any, host: string, port: number): number[] | null {
    return null;
}



/**
 * GetRAKPHash starts an RMCP+ session as username and returns the HMAC the
 * BMC answers with. The session is never completed, so no login is
 * attempted; the BMC drops the half-open session after its timeout. It fails
 * when the BMC rejects the username.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const hash = ipmi.GetRAKPHash('acme.com', 623, 'ADMIN');
 * log(ipmi.CheckRAKPPassword(hash, 'ADMIN'));
 * ```
 */
export function GetRAKPHash(ctx: any, host: string, port: number, username: string): RAKPHash | null {
    return null;
}



/**
 * GetSystemGUID returns the BMC system GUID, which vendors derive from
 * serial numbers or MAC addresses.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const guid = ipmi.GetSystemGUID('acme.com', 623);
 * log(guid);
 * ```
 */
export function GetSystemGUID(ctx: any, host: string, port: number): string | null {
    return null;
}



/**
 * Ping reports whether the host answers an RMCP presence ping and advertises
 * IPMI support.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const isIPMI = ipmi.Ping('acme.com', 623);
 * log(isIPMI);
 * ```
 */
export function Ping(ctx: any, host: string, port: number): boolean | null {
    return null;
}



/**
 * Client holds one RMCP+ session, for commands that need a login.
 * Close it when done: BMCs allow only a few sessions at a time.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const client = new ipmi.Client();
 * client.Login('acme.com', 623, 'ADMIN', 'ADMIN', 3);
 * const id = client.Command(0x06, 0x01, []);
 * client.Close();
 * ```
 */
export class Client {
    

    // Constructor of Client
    constructor() {}
    /**
    * Login opens an RMCP+ session as username with the given cipher suite
    * (0, 1, 2, 3 or 6). Cipher suite 0 skips authentication, so a BMC
    * that allows it accepts any password. A rejected login is an error.
    * @example
    * ```javascript
    * const ipmi = require('nuclei/ipmi');
    * const client = new ipmi.Client();
    * client.Login('acme.com', 623, 'ADMIN', 'not-the-password', 0);
    * ```
    */
    public Login(ctx: any, host: string, port: number, username: string, password: string, cipherSuite: number): boolean | null {
        return null;
    }
    

    /**
    * Command sends an IPMI request in the session, such as Get Device ID
    * (netFn 0x06, cmd 0x01) or Set Session Privilege Level (0x06, 0x3b).
    * @example
    * ```javascript
    * const ipmi = require('nuclei/ipmi');
    * const client = new ipmi.Client();
    * client.Login('acme.com', 623, 'ADMIN', 'ADMIN', 3);
    * const admin = client.Command(0x06, 0x3b, [0x04]).CompletionCode == 0;
    * client.Close();
    * ```
    */
    public Command(netFn: number, cmd: number, data: Uint8Array): CommandResponse | null {
        return null;
    }
    

    /**
    * Close ends the session on the BMC, freeing its slot.
    * @example
    * ```javascript
    * const ipmi = require('nuclei/ipmi');
    * const client = new ipmi.Client();
    * client.Login('acme.com', 623, 'ADMIN', 'ADMIN', 3);
    * client.Close();
    * ```
    */
    public Close(): void {
        return;
    }
    

}



/**
 * AuthCapabilities is what a BMC advertises before any login, from Get
 * Channel Authentication Capabilities.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const caps = ipmi.GetAuthCapabilities('acme.com', 623);
 * log(toJSON(caps));
 * ```
 */
export interface AuthCapabilities {
    
    /**
    * IPMI20 is true when the BMC supports IPMI 2.0 (RMCP+).
    */
    
    IPMI20?: boolean,
    
    /**
    * AuthTypes are the IPMI 1.5 authentication types the channel
    * accepts: none, md2, md5, straight (cleartext password), oem.
    */
    
    AuthTypes?: string[],
    
    /**
    * AnonymousLogin is true when a null username with a null password
    * is accepted.
    */
    
    AnonymousLogin?: boolean,
    
    /**
    * NullUsernames is true when accounts with an empty name are enabled.
    */
    
    NullUsernames?: boolean,
    
    /**
    * NonNullUsernames is true when named accounts are enabled.
    */
    
    NonNullUsernames?: boolean,
    
    /**
    * PerMessageAuth is false when the BMC skips authenticating
    * messages after login.
    */
    
    PerMessageAuth?: boolean,
    
    /**
    * UserLevelAuth is false when user-level commands skip
    * authentication.
    */
    
    UserLevelAuth?: boolean,
    
    /**
    * OEMID is the IANA enterprise number of the BMC vendor, or 0.
    */
    
    OEMID?: number,
}



/**
 * CommandResponse is the reply to an IPMI command.
 */
export interface CommandResponse {
    
    /**
    * CompletionCode is 0 on success.
    */
    
    CompletionCode?: number,
    
    Data?: Uint8Array,
}



/**
 * RAKPHash is the HMAC a BMC returns for a user during RMCP+ session
 * setup (CVE-2013-4786). It can be checked offline against candidate
 * passwords, which tests credentials without a login attempt.
 * @example
 * ```javascript
 * const ipmi = require('nuclei/ipmi');
 * const hash = ipmi.GetRAKPHash('acme.com', 623, 'ADMIN');
 * log(hash.Hashcat);
 * ```
 */
export interface RAKPHash {
    
    Username?: string,
    
    /**
    * Algorithm is the HMAC the BMC used: sha1 or md5.
    */
    
    Algorithm?: string,
    
    /**
    * Salt and HMAC are hex encoded; Salt is everything the HMAC covers.
    */
    
    Salt?: string,
    
    HMAC?: string,
    
    /**
    * Hashcat is the hash in hashcat mode 7300 format, for sha1 only.
    */
    
    Hashcat?: string,
}

