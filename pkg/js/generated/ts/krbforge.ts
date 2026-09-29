

/**
 * CreateGoldenTicket forges a TGT for the supplied user against the given
 * realm using the krbtgt NT hash (or AES key). It returns the ASN.1-encoded
 * ticket and the session key. goimpacket writes <username>.ccache in the current
 * directory, replacing slashes in the username with dots. The destination must
 * be inside the template directory unless -allow-local-file-access is enabled.
 * req.OutputFile must be empty; custom paths and in-memory generation are unsupported.
 * @example
 * ```javascript
 * const krb = require('nuclei/krbforge');
 * const t = krb.CreateGoldenTicket({
 *   username: 'Administrator',
 *   domain:   'acme.local',
 *   domain_sid: 'S-1-5-21-1004336348-1177238915-682003330',
 *   nthash:   '31d6cfe0d16ae931b73c59d7e0c089c0',
 * });
 * log(t.ticket_hex);
 * ```
 */
export function CreateGoldenTicket(req: TicketRequest): Ticket | null {
    return null;
}



/**
 * CreateSilverTicket forges a service ticket (TGS) for the supplied SPN. The
 * hash supplied must belong to the service account that owns the SPN (e.g.
 * the machine account NT hash for cifs/host SPNs).
 * File output follows CreateGoldenTicket. req.OutputFile and outputFile must
 * be empty; custom paths and in-memory generation are unsupported.
 * @example
 * ```javascript
 * const krb = require('nuclei/krbforge');
 * const t = krb.CreateSilverTicket({
 *   username: 'Administrator',
 *   domain:   'acme.local',
 *   domain_sid: 'S-1-5-21-1004336348-1177238915-682003330',
 *   nthash:   '31d6cfe0d16ae931b73c59d7e0c089c0',
 *   spn:      'cifs/server01.acme.local',
 * });
 * log(t.output_file);
 * ```
 */
export function CreateSilverTicket(req: TicketRequest, outputFile?: string): Ticket | null {
    return null;
}



/**
 */
export interface Ticket {
    
    HexTicket?: string,
    
    HexKey?: string,
    
    EncType?: number,
    
    OutputFile?: string,
}



/**
 */
export interface TicketRequest {
    
    Username?: string,
    
    Domain?: string,
    
    DomainSID?: string,
    
    NTHash?: string,
    
    AESKey?: string,
    
    SPN?: string,
    
    UserID?: number,
    
    PrimaryGroupID?: number,
    
    Groups?: number[],
    
    ExtraSIDs?: string[],
    
    DurationHours?: number,
    
    KVNO?: number,
    
    /** Retained for compatibility; must be empty. */
    OutputFile?: string,
}

