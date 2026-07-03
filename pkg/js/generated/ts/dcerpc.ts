

/**
 * NewExecDialer returns a *gptransport.Dialer whose DialFn is bound to the
 * given executionId. Every connection made through the returned dialer is
 * validated against the execution's network policy and routed through the
 * matching fastdialer. Pass it into goimpacket constructors such as
 * smb.NewClientWithDialer or dcerpc.DialTCPWithDialer to guarantee the
 * connection cannot leak across executions.
 */
export function NewExecDialer(execID: string): Dialer | null {
    return null;
}



/**
 * Client is a stateful DCE/RPC + SMB client backed by Mzack9999/goimpacket.
 * One Client wraps one authenticated SMB session against the target host;
 * individual RPC interfaces (SAMR, LSARPC, EPMAPPER, ...) are bound on
 * demand by the corresponding helper methods.
 * @example
 * ```javascript
 * const dcerpc = require('nuclei/dcerpc');
 * const c = new dcerpc.Client('dc01.acme.local', 'acme.local', 'admin', 'P@ssw0rd');
 * const endpoints = c.RpcDump();
 * log(to_json(endpoints));
 * ```
 */
export class Client {
    

    
    public Host?: string;
    

    
    public Domain?: string;
    

    
    public User?: string;
    

    
    public Pass?: string;
    

    
    public NTHash?: string;
    

    
    public KrbCC?: string;
    

    
    public Port?: number;
    

    // Constructor of Client
    constructor(public host: string, public domain: string, public user: string, public password: string ) {}
    

    /**
    * SetHash enables NTLM pass-the-hash authentication.
    * hash may be the bare NT hash or "<lm>:<nt>".
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', '');
    * c.SetHash('aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0');
    * ```
    */
    public SetHash(hash: string): void {
        return;
    }
    

    /**
    * SetKerberos switches the client to Kerberos authentication. dcIP optionally
    * pins the KDC IP when DNS is uncooperative.
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01.acme.local', 'acme.local', 'admin', 'P@ss');
    * c.SetKerberos('10.10.10.10');
    * ```
    */
    public SetKerberos(dcIP: string): void {
        return;
    }
    

    /**
    * SetPort overrides the default SMB port (445).
    */
    public SetPort(port: number): void {
        return;
    }
    

    /**
    * Close releases the underlying SMB session.
    */
    public Close(): void {
        return;
    }
    

    /**
    * RpcDump enumerates every RPC endpoint registered with the EPMAPPER over
    * ncacn_ip_tcp/135 (impacket: rpcdump.py).
    * @example
    * ```javascript
    * const dcerpc = require('nuclei/dcerpc');
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * const eps = c.RpcDump();
    * for (const e of eps) { log(e.UUID + ' ' + e.Annotation); }
    * ```
    */
    public RpcDump(ctx: any): Endpoint[] | null {
        return null;
    }
    

    /**
    * SamrEnumerateUsers connects to SAMR and returns every domain user record
    * (impacket: samrdump.py).
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * const users = c.SamrEnumerateUsers();
    * for (const u of users) { log(u.Name + ' ' + u.RID); }
    * ```
    */
    public SamrEnumerateUsers(): DomainUser[] | null {
        return null;
    }
    

    /**
    * SamrAddComputer creates a new machine account using the supplied password.
    * Useful as the first step in many AD escalations (RBCD / shadow credentials).
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * c.SamrAddComputer('NUCLEI$', 'C0mputerP@ss!');
    * ```
    */
    public SamrAddComputer(name: string): void {
        return;
    }
    

    /**
    * SmbExec executes a Windows command on the target host using the
    * SVCCTL "create + start service" technique (impacket: smbexec.py / psexec.py).
    * The command's stdout/stderr is captured by writing to the chosen share
    * (default C$) and read back over SMB. Local admin equivalent rights are
    * required on the target.
    * command  - the command line to run; for powershell prefix with
    * 	`powershell -EncodedCommand <b64utf16>` or use any cmd one-liner.
    * share    - writable share to stage the output file in (default "C$").
    * @example
    * ```javascript
    * const dcerpc = require('nuclei/dcerpc');
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * const r = c.SmbExec('whoami /all', 'C$');
    * log(r.output);
    * ```
    */
    public SmbExec(command: string): SmbExecResult | null {
        return null;
    }
    

    /**
    * AtExec executes a Windows command on the target host using the Task Scheduler
    * service over the atsvc named pipe (impacket: atexec.py). A one-shot scheduled
    * task is registered as LocalSystem, executed once, and then deleted. The
    * command's stdout/stderr is captured into %windir%\Temp on the chosen share
    * (default ADMIN$) and read back over SMB. Local admin equivalent rights are
    * required on the target.
    * command - the command line to run (wrapped in cmd.exe /C ... by default).
    * share   - writable share to retrieve the output file from (default "ADMIN$").
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * const r = c.AtExec('whoami /all', 'ADMIN$');
    * log(r.output);
    * ```
    */
    public AtExec(command: string, share: string): AtExecResult | null {
        return null;
    }
    

    /**
    * WmiExec executes a Windows command on the target host using DCOM
    * Win32_Process.Create over the WMI IWbemServices interface (impacket:
    * wmiexec.py). The command is launched as a fresh process by the WMI host
    * process and its stdout/stderr is redirected into a temp file on the chosen
    * share (default ADMIN$) which is then read back over SMB. WmiExec is
    * stealthier than SmbExec / AtExec because it does not create a service or a
    * scheduled task, but Win32_Process.Create itself does not return any captured
    * output - the file-tailing roundtrip is required to recover stdout.
    * command - the command line to run; wrapped in cmd.exe /Q /c by default.
    * share   - writable share to retrieve the output file from (default "ADMIN$").
    * Authentication: NTLM with password or pass-the-hash via SetHash. Kerberos is
    * not yet supported on this code path.
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * const r = c.WmiExec('whoami /all', 'ADMIN$');
    * log(r.output);
    * ```
    */
    public WmiExec(command: string, share: string): WmiExecResult | null {
        return null;
    }
    

    /**
    * SmbListShares enumerates the SMB shares exposed by the target.
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * for (const s of c.SmbListShares()) { log(s); }
    * ```
    */
    public SmbListShares(): string[] | null {
        return null;
    }
    

    /**
    * SmbCat reads the contents of a single file from the given share. The path
    * is interpreted relative to the share root (use forward slashes).
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * const txt = c.SmbCat('backup', 'backup_credentials.txt');
    * log(txt);
    * ```
    */
    public SmbCat(share: string): string | null {
        return null;
    }
    

    /**
    * SmbLs Method
    */
    public SmbLs(share: string): FileEntry[] | null {
        return null;
    }
    

    /**
    * LsaLookupSids resolves an array of SIDs to (domain, name, type) triples
    * against LSARPC (impacket: lookupsid.py).
    * @example
    * ```javascript
    * const c = new dcerpc.Client('dc01', 'acme.local', 'admin', 'P@ss');
    * const r = c.LsaLookupSids(['S-1-5-21-...-500']);
    * log(to_json(r));
    * ```
    */
    public LsaLookupSids(sids: string[]): LookupResult[] | null {
        return null;
    }
    

}



/**
 * Dialer Interface
 */
export interface Dialer {
    
    TimeoutSec?: number,
}



/**
 */
export interface FileEntry {
    
    Name?: string,
    
    Size?: number,
    
    IsDir?: boolean,
}



/**
 */
export interface SmbExecResult {
    
    ServiceName?: string,
    
    Output?: string,
}



/**
 */
export interface AtExecResult {
    
    TaskName?: string,
    
    Output?: string,
}



/**
 */
export interface WmiExecResult {
    
    ReturnValue?: number,
    
    Output?: string,
}

