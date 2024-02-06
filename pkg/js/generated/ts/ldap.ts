

/** The user account is disabled. */
export const FilterAccountDisabled = "(userAccountControl:1.2.840.113556.1.4.803:=2)";

/** The user account is enabled. */
export const FilterAccountEnabled = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))";

/** The user can send an encrypted password. */
export const FilterCanSendEncryptedPassword = "(userAccountControl:1.2.840.113556.1.4.803:=128)";

/** Represents the password, which should never expire on the account. */
export const FilterDontExpirePassword = "(userAccountControl:1.2.840.113556.1.4.803:=65536)";

/** This account doesn't require Kerberos pre-authentication for logging on. */
export const FilterDontRequirePreauth = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";


export const FilterHasServicePrincipalName = "(servicePrincipalName=*)";

/** The home folder is required. */
export const FilterHomedirRequired = "(userAccountControl:1.2.840.113556.1.4.803:=8)";

/** It's a permit to trust an account for a system domain that trusts other domains. */
export const FilterInterdomainTrustAccount = "(userAccountControl:1.2.840.113556.1.4.803:=2048)";


export const FilterIsAdmin = "(adminCount=1)";


export const FilterIsComputer = "(objectCategory=computer)";

/** It's an account for users whose primary account is in another domain. */
export const FilterIsDuplicateAccount = "(userAccountControl:1.2.840.113556.1.4.803:=256)";


export const FilterIsGroup = "(objectCategory=group)";

/** It's a default account type that represents a typical user. */
export const FilterIsNormalAccount = "(userAccountControl:1.2.840.113556.1.4.803:=512)";


export const FilterIsPerson = "(objectCategory=person)";

/** The user is locked out. */
export const FilterLockout = "(userAccountControl:1.2.840.113556.1.4.803:=16)";

/** The logon script will be run. */
export const FilterLogonScript = "(userAccountControl:1.2.840.113556.1.4.803:=1)";

/** It's an MNS logon account. */
export const FilterMnsLogonAccount = "(userAccountControl:1.2.840.113556.1.4.803:=131072)";

/** When this flag is set, the security context of the user isn't delegated to a service even if the service account is set as trusted for Kerberos delegation. */
export const FilterNotDelegated = "(userAccountControl:1.2.840.113556.1.4.803:=1048576)";

/** The account is a read-only domain controller (RODC). */
export const FilterPartialSecretsAccount = "(userAccountControl:1.2.840.113556.1.4.803:=67108864)";

/** The user can't change the password. */
export const FilterPasswordCantChange = "(userAccountControl:1.2.840.113556.1.4.803:=64)";

/** The user's password has expired. */
export const FilterPasswordExpired = "(userAccountControl:1.2.840.113556.1.4.803:=8388608)";

/** No password is required. */
export const FilterPasswordNotRequired = "(userAccountControl:1.2.840.113556.1.4.803:=32)";

/** It's a computer account for a domain controller that is a member of this domain. */
export const FilterServerTrustAccount = "(userAccountControl:1.2.840.113556.1.4.803:=8192)";

/** When this flag is set, it forces the user to log on by using a smart card. */
export const FilterSmartCardRequired = "(userAccountControl:1.2.840.113556.1.4.803:=262144)";

/** When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation. */
export const FilterTrustedForDelegation = "(userAccountControl:1.2.840.113556.1.4.803:=524288)";

/** The account is enabled for delegation. */
export const FilterTrustedToAuthForDelegation = "(userAccountControl:1.2.840.113556.1.4.803:=16777216)";

/** Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys. */
export const FilterUseDesKeyOnly = "(userAccountControl:1.2.840.113556.1.4.803:=2097152)";

/** It's a computer account for a computer that is running old Windows builds. */
export const FilterWorkstationTrustAccount = "(userAccountControl:1.2.840.113556.1.4.803:=4096)";

/**
 * DecodeADTimestamp decodes an Active Directory timestamp
 */
export function DecodeADTimestamp(timestamp: string): string {
    return "";
}



/**
 * DecodeSID decodes a SID string
 */
export function DecodeSID(s: string): string {
    return "";
}



/**
 * DecodeZuluTimestamp decodes a Zulu timestamp
 * example: 2021-08-25T14:00:00Z
 */
export function DecodeZuluTimestamp(timestamp: string): string {
    return "";
}



/**
 * JoinFilters joins multiple filters into a single filter
 */
export function JoinFilters(filters: any): string {
    return "";
}



/**
 * NegativeFilter returns a negative filter for a given filter
 */
export function NegativeFilter(filter: string): string {
    return "";
}



/**
 * Client Class
 */
export class Client {
    

    
    public Host?: string;
    

    
    public Port?: number;
    

    
    public Realm?: string;
    

    
    public BaseDN?: string;
    

    // Constructor of Client
    constructor(public ldapUrl: string, public realm: string, public config?: Config ) {}
    

    /**
    * FindADObjects finds AD objects based on a filter
    * and returns them as a list of ADObject
    * @param filter: string
    * @return []ADObject
    */
    public FindADObjects(filter: string): ADObject[] {
        return [];
    }
    

    /**
    * GetADUsers returns all AD users
    * using FilterIsPerson filter query
    * @return []ADObject
    */
    public GetADUsers(): ADObject[] {
        return [];
    }
    

    /**
    * GetADActiveUsers returns all AD users
    * using FilterIsPerson and FilterAccountEnabled filter query
    * @return []ADObject
    */
    public GetADActiveUsers(): ADObject[] {
        return [];
    }
    

    /**
    * GetAdUserWithNeverExpiringPasswords returns all AD users
    * using FilterIsPerson and FilterDontExpirePassword filter query
    * @return []ADObject
    */
    public GetADUserWithNeverExpiringPasswords(): ADObject[] {
        return [];
    }
    

    /**
    * GetADUserTrustedForDelegation returns all AD users that are trusted for delegation
    * using FilterIsPerson and FilterTrustedForDelegation filter query
    * @return []ADObject
    */
    public GetADUserTrustedForDelegation(): ADObject[] {
        return [];
    }
    

    /**
    * GetADUserWithPasswordNotRequired returns all AD users that do not require a password
    * using FilterIsPerson and FilterPasswordNotRequired filter query
    * @return []ADObject
    */
    public GetADUserWithPasswordNotRequired(): ADObject[] {
        return [];
    }
    

    /**
    * GetADGroups returns all AD groups
    * using FilterIsGroup filter query
    * @return []ADObject
    */
    public GetADGroups(): ADObject[] {
        return [];
    }
    

    /**
    * GetADDCList returns all AD domain controllers
    * using FilterIsComputer, FilterAccountEnabled and FilterServerTrustAccount filter query
    * @return []ADObject
    */
    public GetADDCList(): ADObject[] {
        return [];
    }
    

    /**
    * GetADAdmins returns all AD admins
    * using FilterIsPerson, FilterAccountEnabled and FilterIsAdmin filter query
    * @return []ADObject
    */
    public GetADAdmins(): ADObject[] {
        return [];
    }
    

    /**
    * GetADUserKerberoastable returns all AD users that are kerberoastable
    * using FilterIsPerson, FilterAccountEnabled and FilterHasServicePrincipalName filter query
    * @return []ADObject
    */
    public GetADUserKerberoastable(): ADObject[] {
        return [];
    }
    

    /**
    * GetADDomainSID returns the SID of the AD domain
    * @return string
    */
    public GetADDomainSID(): string {
        return "";
    }
    

    /**
    * Authenticate authenticates with the ldap server using the given username and password
    * performs NTLMBind first and then Bind/UnauthenticatedBind if NTLMBind fails
    * Signature: Authenticate(username, password)
    * @param username: string
    * @param password: string (can be empty for unauthenticated bind)
    * @throws error if authentication fails
    */
    public Authenticate(username: string): void {
        return;
    }
    

    /**
    * AuthenticateWithNTLMHash authenticates with the ldap server using the given username and NTLM hash
    * Signature: AuthenticateWithNTLMHash(username, hash)
    * @param username: string
    * @param hash: string
    * @throws error if authentication fails
    */
    public AuthenticateWithNTLMHash(username: string): void {
        return;
    }
    

    /**
    * Search accepts whatever filter and returns a list of maps having provided attributes
    * as keys and associated values mirroring the ones returned by ldap
    * Signature: Search(filter, attributes...)
    * @param filter: string
    * @param attributes: ...string
    * @return []map[string][]string
    */
    public Search(filter: string, attributes: any): Record<string, string[]>[] {
        return [];
    }
    

    /**
    * AdvancedSearch accepts all values of search request type and return Ldap Entry
    * its up to user to handle the response
    * Signature: AdvancedSearch(Scope, DerefAliases, SizeLimit, TimeLimit, TypesOnly, Filter, Attributes, Controls)
    * @param Scope: int
    * @param DerefAliases: int
    * @param SizeLimit: int
    * @param TimeLimit: int
    * @param TypesOnly: bool
    * @param Filter: string
    * @param Attributes: []string
    * @param Controls: []ldap.Control
    * @return ldap.SearchResult
    */
    public AdvancedSearch(Scope: number, TypesOnly: boolean, Filter: string, Attributes: string[], Controls: any): SearchResult | null {
        return null;
    }
    

    /**
    * CollectLdapMetadata collects metadata from ldap server.
    * Signature: CollectMetadata(domain, controller)
    * @return Metadata
    */
    public CollectMetadata(): Metadata | null {
        return null;
    }
    

    /**
    * close the ldap connection
    */
    public Close(): void {
        return;
    }
    

}



/**
 * ADObject interface
 */
export interface ADObject {
    
    DistinguishedName?: string,
    
    SAMAccountName?: string,
    
    PWDLastSet?: string,
    
    LastLogon?: string,
    
    MemberOf?: string[],
    
    ServicePrincipalName?: string[],
}



/**
 * Config interface
 */
export interface Config {
    
    /**
    * Timeout is the timeout for the ldap client in seconds
    */
    
    Timeout?: number,
    
    ServerName?: string,
    
    Upgrade?: boolean,
}



/**
 * Entry Interface
 */
export interface Entry {
    
    DN?: string,
    
    Attributes?: EntryAttribute,
}



/**
 * EntryAttribute Interface
 */
export interface EntryAttribute {
    
    Name?: string,
    
    Values?: string[],
    
    ByteValues?: Uint8Array,
}



/**
 * Metadata interface
 */
export interface Metadata {
    
    BaseDN?: string,
    
    Domain?: string,
    
    DefaultNamingContext?: string,
    
    DomainFunctionality?: string,
    
    ForestFunctionality?: string,
    
    DomainControllerFunctionality?: string,
    
    DnsHostName?: string,
}



/**
 * SearchResult Interface
 */
export interface SearchResult {
    
    Referrals?: string[],
    
    Entries?: Entry,
}

