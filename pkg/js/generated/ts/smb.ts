

/**
 * SMBClient is a client for SMB servers.
 * Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver.
 * github.com/projectdiscovery/go-smb2 driver
 * @example
 * ```javascript
 * const smb = require('nuclei/smb');
 * const client = new smb.SMBClient();
 * ```
 */
export class SMBClient {
    

    // Constructor of SMBClient
    constructor() {}
    /**
    * ConnectSMBInfoMode tries to connect to provided host and port
    * and discovery SMB information
    * Returns handshake log and error. If error is not nil,
    * state will be false
    * @example
    * ```javascript
    * const smb = require('nuclei/smb');
    * const client = new smb.SMBClient();
    * const info = client.ConnectSMBInfoMode('acme.com', 445);
    * log(to_json(info));
    * ```
    */
    public ConnectSMBInfoMode(host: string, port: number): SMBLog | null | null {
        return null;
    }
    

    /**
    * ListSMBv2Metadata tries to connect to provided host and port
    * and list SMBv2 metadata.
    * Returns metadata and error. If error is not nil,
    * state will be false
    * @example
    * ```javascript
    * const smb = require('nuclei/smb');
    * const client = new smb.SMBClient();
    * const metadata = client.ListSMBv2Metadata('acme.com', 445);
    * log(to_json(metadata));
    * ```
    */
    public ListSMBv2Metadata(host: string, port: number): ServiceSMB | null | null {
        return null;
    }
    

    /**
    * ListShares tries to connect to provided host and port
    * and list shares by using given credentials.
    * Credentials cannot be blank. guest or anonymous credentials
    * can be used by providing empty password.
    * @example
    * ```javascript
    * const smb = require('nuclei/smb');
    * const client = new smb.SMBClient();
    * const shares = client.ListShares('acme.com', 445, 'username', 'password');
    * 	for (const share of shares) {
    * 		  log(share);
    * 	}
    * ```
    */
    public ListShares(host: string, port: number, user: string): string[] | null {
        return null;
    }
    

    /**
    * DetectSMBGhost tries to detect SMBGhost vulnerability
    * by using SMBv3 compression feature.
    * If the host is vulnerable, it returns true.
    * @example
    * ```javascript
    * const smb = require('nuclei/smb');
    * const isSMBGhost = smb.DetectSMBGhost('acme.com', 445);
    * ```
    */
    public DetectSMBGhost(host: string, port: number): boolean | null {
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
    
    SecurityMode?: number,
    
    DialectRevision?: number,
    
    ServerGuid?: Uint8Array,
    
    Capabilities?: number,
    
    SystemTime?: number,
    
    ServerStartTime?: number,
    
    AuthenticationTypes?: string[],
    
    HeaderLog?: HeaderLog,
}



/**
 * SMBCapabilities Interface
 */
export interface SMBCapabilities {
    
    DFSSupport?: boolean,
    
    Leasing?: boolean,
    
    LargeMTU?: boolean,
    
    MultiChan?: boolean,
    
    Persist?: boolean,
    
    DirLeasing?: boolean,
    
    Encryption?: boolean,
}



/**
 * SMBLog Interface
 */
export interface SMBLog {
    
    NTLM?: string,
    
    GroupName?: string,
    
    HasNTLM?: boolean,
    
    SupportV1?: boolean,
    
    NativeOs?: string,
    
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
    
    OSVersion?: string,
    
    NetBIOSComputerName?: string,
    
    NetBIOSDomainName?: string,
    
    DNSComputerName?: string,
    
    DNSDomainName?: string,
    
    ForestName?: string,
    
    SigningEnabled?: boolean,
    
    SigningRequired?: boolean,
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

