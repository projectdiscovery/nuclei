
/**
 * SMBClient Class
 */
export class SMBClient {
    

    /**
    * ConnectSMBInfoMode tries to connect to provided host and port
    * and discovery SMB information
    * Returns handshake log and error. If error is not nil,
    * state will be false
    * @throws {Error} - if the operation fails
    */
    public ConnectSMBInfoMode(host: string, port: number): SMBLog | null {
        return null;
    }
    

    /**
    * ListSMBv2Metadata tries to connect to provided host and port
    * and list SMBv2 metadata.
    * Returns metadata and error. If error is not nil,
    * state will be false
    * @throws {Error} - if the operation fails
    */
    public ListSMBv2Metadata(host: string, port: number): ServiceSMB | null {
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
 * SessionSetupLog Interface
 */
export interface SessionSetupLog {
    
    TargetName?: string,
    
    NegotiateFlags?: number,
    
    SetupFlags?: number,
    
    HeaderLog?: HeaderLog,
}


/**
 * SMBVersions Interface
 */
export interface SMBVersions {
    
    VerString?: string,
    
    Major?: number,
    
    Minor?: number,
    
    Revision?: number,
}


/**
 * SMBCapabilities Interface
 */
export interface SMBCapabilities {
    
    Persist?: boolean,
    
    DirLeasing?: boolean,
    
    Encryption?: boolean,
    
    DFSSupport?: boolean,
    
    Leasing?: boolean,
    
    LargeMTU?: boolean,
    
    MultiChan?: boolean,
}


/**
 * NegotiationLog Interface
 */
export interface NegotiationLog {
    
    AuthenticationTypes?: string[],
    
    SecurityMode?: number,
    
    DialectRevision?: number,
    
    ServerGuid?: Uint8Array,
    
    Capabilities?: number,
    
    SystemTime?: number,
    
    ServerStartTime?: number,
    
    HeaderLog?: HeaderLog,
}


/**
 * SMBLog Interface
 */
export interface SMBLog {
    
    HasNTLM?: boolean,
    
    SupportV1?: boolean,
    
    NativeOs?: string,
    
    NTLM?: string,
    
    GroupName?: string,
    
    SessionSetupLog?: SessionSetupLog,
    
    Version?: SMBVersions,
    
    Capabilities?: SMBCapabilities,
    
    NegotiationLog?: NegotiationLog,
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

