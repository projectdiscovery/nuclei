

/**
 * ASRepToHashcat converts an AS-REP message to a hashcat format
* @throws {Error} - if the operation fails
 */
export function ASRepToHashcat(asrep: any): string | null {
    return null;
}



/**
 * CheckKrbError checks if the response bytes from the KDC are a KRBError.
* @throws {Error} - if the operation fails
 */
export function CheckKrbError(b: Uint8Array): Uint8Array | null {
    return null;
}



/**
 * NewKerberosClientFromString creates a new kerberos client from a string
 * by parsing krb5.conf
 * @param cfg: string
 * Example krb5.conf:
 * [libdefaults]
 * default_realm = ACME.COM
 * dns_lookup_kdc = true
* @throws {Error} - if the operation fails
 */
export function NewKerberosClientFromString(cfg: string): Client | null {
    return null;
}



/**
 * sendtokdc.go deals with actual sending and receiving responses from KDC
 * SendToKDC sends a message to the KDC and returns the response.
* @throws {Error} - if the operation fails
 */
export function SendToKDC(kclient: Client, msg: string): string | null {
    return null;
}



/**
 * TGStoHashcat converts a TGS to a hashcat format.
* @throws {Error} - if the operation fails
 */
export function TGStoHashcat(tgs: any, username: string): string | null {
    return null;
}



/**
 * Client Class
 */
export class Client {
    

    
    public Krb5Config?: Config;
    

    
    public Realm?: string;
    

    // Constructor of Client
    constructor(public domain: string, public controller?: string ) {}
    

    /**
    * SetConfig sets additional config for the kerberos client
    * Signature: SetConfig(cfg)
    * @param cfg: @Config
    * Note: as of now ip and timeout overrides are only supported
    * in EnumerateUser due to fastdialer but can be extended to other methods currently
    */
    public SetConfig(cfg: Config): void {
        return;
    }
    

    /**
    * EnumerateUser and attempt to get AS-REP hash by disabling PA-FX-FAST
    * Signature: EnumerateUser(username, {password})
    * @param username: string
    * @throws {Error} - if the operation fails
    */
    public EnumerateUser(username: string): EnumerateUserResponse | null {
        return null;
    }
    

    /**
    * GetServiceTicket returns a TGS for a given user, password, target and SPN
    * Signature: GetServiceTicket(User, Pass, Target, SPN)
    * @param User: string
    * @param Pass: string
    * @param SPN: string Service Principal Name
    * @throws {Error} - if the operation fails
    */
    public GetServiceTicket(User: string): TGS | null {
        return null;
    }
    

}



/**
 * Config Class
 */
export class Config {
    

    // Constructor of Config
    constructor() {}
    /**
    * SetIPAddress Method
    */
    public SetIPAddress(ip: string): Config | null {
        return null;
    }
    

    /**
    * SetTimeout Method
    */
    public SetTimeout(timeout: number): Config | null {
        return null;
    }
    

}



/**
 * AuthorizationDataEntry Interface
 */
export interface AuthorizationDataEntry {
    
    ADType?: number,
    
    ADData?: Uint8Array,
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
    
    CRealm?: string,
    
    AuthTime?: Date,
    
    StartTime?: Date,
    
    EndTime?: Date,
    
    RenewTill?: Date,
    
    Key?: EncryptionKey,
    
    CName?: PrincipalName,
    
    Transited?: TransitedEncoding,
    
    CAddr?: HostAddress,
    
    AuthorizationData?: AuthorizationDataEntry,
    
    Flags?: BitString,
}



/**
 * EncryptedData Interface
 */
export interface EncryptedData {
    
    Cipher?: Uint8Array,
    
    EType?: number,
    
    KVNO?: number,
}



/**
 * EncryptionKey Interface
 */
export interface EncryptionKey {
    
    KeyType?: number,
    
    KeyValue?: Uint8Array,
}



/**
 * EnumerateUserResponse interface
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
    
    NoAddresses?: boolean,
    
    SafeChecksumType?: number,
    
    ExtraAddresses?: Uint8Array,
    
    IgnoreAcceptorHostname?: boolean,
    
    VerifyAPReqNofail?: boolean,
    
    CCacheType?: number,
    
    DefaultClientKeytabName?: string,
    
    K5LoginAuthoritative?: boolean,
    
    /**
    * time in nanoseconds
    */
    
    RenewLifetime?: number,
    
    DefaultTGSEnctypeIDs?: number[],
    
    DefaultTktEnctypeIDs?: number[],
    
    DNSLookupRealm?: boolean,
    
    PreferredPreauthTypes?: number[],
    
    /**
    * time in nanoseconds
    */
    
    TicketLifetime?: number,
    
    Forwardable?: boolean,
    
    PermittedEnctypes?: string[],
    
    PermittedEnctypeIDs?: number[],
    
    RDNS?: boolean,
    
    Canonicalize?: boolean,
    
    DefaultRealm?: string,
    
    DefaultTGSEnctypes?: string[],
    
    DefaultTktEnctypes?: string[],
    
    DNSCanonicalizeHostname?: boolean,
    
    AllowWeakCrypto?: boolean,
    
    /**
    * time in nanoseconds
    */
    
    Clockskew?: number,
    
    K5LoginDirectory?: string,
    
    KDCTimeSync?: number,
    
    Proxiable?: boolean,
    
    RealmTryDomains?: number,
    
    DefaultKeytabName?: string,
    
    DNSLookupKDC?: boolean,
    
    UDPPreferenceLimit?: number,
    
    KDCDefaultOptions?: BitString,
}



/**
 * PrincipalName Interface
 */
export interface PrincipalName {
    
    NameType?: number,
    
    NameString?: string[],
}



/**
 * Realm Interface
 */
export interface Realm {
    
    KPasswdServer?: string[],
    
    MasterKDC?: string[],
    
    Realm?: string,
    
    AdminServer?: string[],
    
    DefaultDomain?: string,
    
    KDC?: string[],
}



/**
 * TGS interface
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

