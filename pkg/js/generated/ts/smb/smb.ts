

/**
 * DetectSMBGhost tries to detect SMBGhost vulnerability
 * by using SMBv3 compression feature.
* @throws {Error} - if the operation fails
 */
export function DetectSMBGhost(host: string, port: number): boolean | null {
    return null;
}



/**
 * SMBClient Class
 */
export class SMBClient {
    

    // Constructor of SMBClient
    constructor() {}
    /**
    * ConnectSMBInfoMode tries to connect to provided host and port
    * and discovery SMB information
    * Returns handshake log and error. If error is not nil,
    * state will be false
    * @throws {Error} - if the operation fails
    */
    public ConnectSMBInfoMode(host: string, port: number): SMBLog | null | null {
        return null;
    }
    

    /**
    * ListSMBv2Metadata tries to connect to provided host and port
    * and list SMBv2 metadata.
    * Returns metadata and error. If error is not nil,
    * state will be false
    * @throws {Error} - if the operation fails
    */
    public ListSMBv2Metadata(host: string, port: number): ServiceSMB | null | null {
        return null;
    }
    

    /**
    * ListShares tries to connect to provided host and port
    * and list shares by using given credentials.
    * Credentials cannot be blank. guest or anonymous credentials
    * can be used by providing empty password.
    * @throws {Error} - if the operation fails
    */
    public ListShares(host: string, port: number, user: string): string[] | null {
        return null;
    }
    

}



/**
 * HeaderLog Interface
 */
export interface HeaderLog {
    
    ProtocolID?: Uint8Array,
    
    Status?: number,
    
    Command?: number,
    
    Credits?: number,
    
    Flags?: number,
}



/**
 * NegotiationLog Interface
 */
export interface NegotiationLog {
    
    SystemTime?: number,
    
    ServerStartTime?: number,
    
    AuthenticationTypes?: string[],
    
    SecurityMode?: number,
    
    DialectRevision?: number,
    
    ServerGuid?: Uint8Array,
    
    Capabilities?: number,
    
    HeaderLog?: HeaderLog,
}



/**
 * SMBCapabilities Interface
 */
export interface SMBCapabilities {
    
    Encryption?: boolean,
    
    DFSSupport?: boolean,
    
    Leasing?: boolean,
    
    LargeMTU?: boolean,
    
    MultiChan?: boolean,
    
    Persist?: boolean,
    
    DirLeasing?: boolean,
}



/**
 * SMBLog Interface
 */
export interface SMBLog {
    
    SupportV1?: boolean,
    
    NativeOs?: string,
    
    NTLM?: string,
    
    GroupName?: string,
    
    HasNTLM?: boolean,
    
    Version?: SMBVersions,
    
    Capabilities?: SMBCapabilities,
    
    NegotiationLog?: NegotiationLog,
    
    SessionSetupLog?: SessionSetupLog,
}



/**
 * SMBVersions Interface
 */
export interface SMBVersions {
    
    Major?: number,
    
    Minor?: number,
    
    Revision?: number,
    
    VerString?: string,
}



/**
 * ServiceSMB Interface
 */
export interface ServiceSMB {
    
    NetBIOSComputerName?: string,
    
    NetBIOSDomainName?: string,
    
    DNSComputerName?: string,
    
    DNSDomainName?: string,
    
    ForestName?: string,
    
    SigningEnabled?: boolean,
    
    SigningRequired?: boolean,
    
    OSVersion?: string,
}



/**
 * SessionSetupLog Interface
 */
export interface SessionSetupLog {
    
    SetupFlags?: number,
    
    TargetName?: string,
    
    NegotiateFlags?: number,
    
    HeaderLog?: HeaderLog,
}

