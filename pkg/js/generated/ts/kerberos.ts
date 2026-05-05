

/**
 * ASRepToHashcat converts an AS-REP message to a hashcat format
 */
export function ASRepToHashcat(asrep: any): string | null {
    return null;
}



/**
 * CheckKrbError checks if the response bytes from the KDC are a KRBError.
 */
export function CheckKrbError(b: Uint8Array): Uint8Array | null {
    return null;
}



/**
 * NewKerberosClientFromString creates a new kerberos client from a string
 * by parsing krb5.conf
 * @example
 * ```javascript
 * const kerberos = require('nuclei/kerberos');
 * const client = kerberos.NewKerberosClientFromString(`
 * [libdefaults]
 * default_realm = ACME.COM
 * dns_lookup_kdc = true
 * `);
 * ```
 */
export function NewKerberosClientFromString(cfg: string): Client | null {
    return null;
}



/**
 * sendtokdc.go deals with actual sending and receiving responses from KDC
 * SendToKDC sends a message to the KDC and returns the response.
 * It first tries to send the message over TCP, and if that fails, it falls back to UDP.(and vice versa)
 * @example
 * ```javascript
 * const kerberos = require('nuclei/kerberos');
 * const client = new kerberos.Client('acme.com');
 * const response = kerberos.SendToKDC(client, 'message');
 * ```
 */
export function SendToKDC(kclient: Client, msg: string): string | null {
    return null;
}



/**
 * TGStoHashcat converts a TGS to a hashcat format.
 */
export function TGStoHashcat(tgs: any, username: string): string | null {
    return null;
}



/**
 * Known Issues:
 * Hardcoded timeout in gokrb5 library
 * TGT / Session Handling not exposed
 * Client is kerberos client
 * @example
 * ```javascript
 * const kerberos = require('nuclei/kerberos');
 * // if controller is empty a dns lookup for default kdc server will be performed
 * const client = new kerberos.Client('acme.com', 'kdc.acme.com');
 * ```
 */
export class Client {
    

    
    public Krb5Config?: Config;
    

    
    public Realm?: string;
    

    // Constructor of Client
    constructor(public domain: string, public controller?: string ) {}
    

    /**
    * SetConfig sets additional config for the kerberos client
    * Note: as of now ip and timeout overrides are only supported
    * in EnumerateUser due to fastdialer but can be extended to other methods currently
    * @example
    * ```javascript
    * const kerberos = require('nuclei/kerberos');
    * const client = new kerberos.Client('acme.com', 'kdc.acme.com');
    * const cfg = new kerberos.Config();
    * cfg.SetIPAddress('192.168.100.22');
    * cfg.SetTimeout(5);
    * client.SetConfig(cfg);
    * ```
    */
    public SetConfig(cfg: Config): void {
        return;
    }
    

    /**
    * EnumerateUser and attempt to get AS-REP hash by disabling PA-FX-FAST
    * @example
    * ```javascript
    * const kerberos = require('nuclei/kerberos');
    * const client = new kerberos.Client('acme.com', 'kdc.acme.com');
    * const resp = client.EnumerateUser('pdtm');
    * log(resp);
    * ```
    */
    public EnumerateUser(username: string): EnumerateUserResponse | null {
        return null;
    }
    

    /**
    * GetServiceTicket returns a TGS for a given user, password and SPN
    * @example
    * ```javascript
    * const kerberos = require('nuclei/kerberos');
    * const client = new kerberos.Client('acme.com', 'kdc.acme.com');
    * const resp = client.GetServiceTicket('pdtm', 'password', 'HOST/CLIENT1');
    * log(resp);
    * ```
    */
    public GetServiceTicket(User: string): TGS | null {
        return null;
    }
    

}



/**
 * Config is extra configuration for the kerberos client
 */
export class Config {
    

    // Constructor of Config
    constructor() {}
    /**
    * SetIPAddress sets the IP address for the kerberos client
    * @example
    * ```javascript
    * const kerberos = require('nuclei/kerberos');
    * const cfg = new kerberos.Config();
    * cfg.SetIPAddress('10.10.10.1');
    * ```
    */
    public SetIPAddress(ip: string): Config | null {
        return null;
    }
    

    /**
    * SetTimeout sets the RW timeout for the kerberos client
    * @example
    * ```javascript
    * const kerberos = require('nuclei/kerberos');
    * const cfg = new kerberos.Config();
    * cfg.SetTimeout(5);
    * ```
    */
    public SetTimeout(timeout: number): Config | null {
        return null;
    }
    

}



/**
 * AuthorizationDataEntry Interface
 */
export interface AuthorizationDataEntry {
    
    ADData?: Uint8Array,
    
    ADType?: number,
}



/**
 * BitString Interface
 */
export interface BitString {
    
    Bytes?: Uint8Array,
    
    BitLength?: number,
}



/**
 * BitString Interface
 */
export interface BitString {
    
    Bytes?: Uint8Array,
    
    BitLength?: number,
}



/**
 * Config Interface
 */
export interface Config {
    
    LibDefaults?: LibDefaults,
    
    Realms?: Realm,
}



/**
 * EncTicketPart Interface
 */
export interface EncTicketPart {
    
    EndTime?: Date,
    
    RenewTill?: Date,
    
    CRealm?: string,
    
    AuthTime?: Date,
    
    StartTime?: Date,
    
    Flags?: BitString,
    
    Key?: EncryptionKey,
    
    CName?: PrincipalName,
    
    Transited?: TransitedEncoding,
    
    CAddr?: HostAddress,
    
    AuthorizationData?: AuthorizationDataEntry,
}



/**
 * EncryptedData Interface
 */
export interface EncryptedData {
    
    EType?: number,
    
    KVNO?: number,
    
    Cipher?: Uint8Array,
}



/**
 * EncryptionKey Interface
 */
export interface EncryptionKey {
    
    KeyType?: number,
    
    KeyValue?: Uint8Array,
}



/**
 * EnumerateUserResponse is the response from EnumerateUser
 */
export interface EnumerateUserResponse {
    
    Valid?: boolean,
    
    ASREPHash?: string,
    
    Error?: string,
}



/**
 * HostAddress Interface
 */
export interface HostAddress {
    
    AddrType?: number,
    
    Address?: Uint8Array,
}



/**
 * LibDefaults Interface
 */
export interface LibDefaults {
    
    CCacheType?: number,
    
    K5LoginAuthoritative?: boolean,
    
    Proxiable?: boolean,
    
    RDNS?: boolean,
    
    K5LoginDirectory?: string,
    
    KDCTimeSync?: number,
    
    VerifyAPReqNofail?: boolean,
    
    DefaultTGSEnctypes?: string[],
    
    DefaultTGSEnctypeIDs?: number[],
    
    DNSCanonicalizeHostname?: boolean,
    
    Forwardable?: boolean,
    
    /**
    * time in nanoseconds
    */
    
    RenewLifetime?: number,
    
    /**
    * time in nanoseconds
    */
    
    TicketLifetime?: number,
    
    DefaultClientKeytabName?: string,
    
    DefaultTktEnctypeIDs?: number[],
    
    DNSLookupRealm?: boolean,
    
    ExtraAddresses?: Uint8Array,
    
    DefaultRealm?: string,
    
    NoAddresses?: boolean,
    
    PreferredPreauthTypes?: number[],
    
    PermittedEnctypeIDs?: number[],
    
    RealmTryDomains?: number,
    
    DefaultKeytabName?: string,
    
    DefaultTktEnctypes?: string[],
    
    DNSLookupKDC?: boolean,
    
    IgnoreAcceptorHostname?: boolean,
    
    AllowWeakCrypto?: boolean,
    
    Canonicalize?: boolean,
    
    SafeChecksumType?: number,
    
    UDPPreferenceLimit?: number,
    
    /**
    * time in nanoseconds
    */
    
    Clockskew?: number,
    
    PermittedEnctypes?: string[],
    
    KDCDefaultOptions?: BitString,
}



/**
 * PrincipalName Interface
 */
export interface PrincipalName {
    
    NameString?: string[],
    
    NameType?: number,
}



/**
 * Realm Interface
 */
export interface Realm {
    
    Realm?: string,
    
    AdminServer?: string[],
    
    DefaultDomain?: string,
    
    KDC?: string[],
    
    KPasswdServer?: string[],
    
    MasterKDC?: string[],
}



/**
 * TGS is the response from GetServiceTicket
 */
export interface TGS {
    
    Ticket?: Ticket,
    
    Hash?: string,
    
    ErrMsg?: string,
}



/**
 * Ticket Interface
 */
export interface Ticket {
    
    TktVNO?: number,
    
    Realm?: string,
    
    SName?: PrincipalName,
    
    EncPart?: EncryptedData,
    
    DecryptedEncPart?: EncTicketPart,
}



/**
 * TransitedEncoding Interface
 */
export interface TransitedEncoding {
    
    TRType?: number,
    
    Contents?: Uint8Array,
}

