

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

/** The object has a service principal name. */
export const FilterHasServicePrincipalName = "(servicePrincipalName=*)";

/** The home folder is required. */
export const FilterHomedirRequired = "(userAccountControl:1.2.840.113556.1.4.803:=8)";

/** It's a permit to trust an account for a system domain that trusts other domains. */
export const FilterInterdomainTrustAccount = "(userAccountControl:1.2.840.113556.1.4.803:=2048)";

/** The object is an admin. */
export const FilterIsAdmin = "(adminCount=1)";

/** The object is a computer. */
export const FilterIsComputer = "(objectCategory=computer)";

/** It's an account for users whose primary account is in another domain. */
export const FilterIsDuplicateAccount = "(userAccountControl:1.2.840.113556.1.4.803:=256)";

/** The object is a group. */
export const FilterIsGroup = "(objectCategory=group)";

/** It's a default account type that represents a typical user. */
export const FilterIsNormalAccount = "(userAccountControl:1.2.840.113556.1.4.803:=512)";

/** The object is a person. */
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
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * const timestamp = ldap.DecodeADTimestamp('132036744000000000');
 * log(timestamp);
 * ```
 */
export function DecodeADTimestamp(timestamp: string): string {
    return "";
}



/**
 * DecodeSID decodes a SID string
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * const sid = ldap.DecodeSID('S-1-5-21-3623811015-3361044348-30300820-1013');
 * log(sid);
 * ```
 */
export function DecodeSID(s: string): string {
    return "";
}



/**
 * DecodeZuluTimestamp decodes a Zulu timestamp
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * const timestamp = ldap.DecodeZuluTimestamp('2021-08-25T10:00:00Z');
 * log(timestamp);
 * ```
 */
export function DecodeZuluTimestamp(timestamp: string): string {
    return "";
}



/**
 * JoinFilters joins multiple filters into a single filter
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * const filter = ldap.JoinFilters(ldap.FilterIsPerson, ldap.FilterAccountEnabled);
 * ```
 */
export function JoinFilters(filters: any): string {
    return "";
}



/**
 * NegativeFilter returns a negative filter for a given filter
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * const filter = ldap.NegativeFilter(ldap.FilterIsPerson);
 * ```
 */
export function NegativeFilter(filter: string): string {
    return "";
}



/**
 * Client is a client for ldap protocol in nuclei
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * // here ldap.example.com is the ldap server and acme.com is the realm
 * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
 * ```
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * const cfg = new ldap.Config();
 * cfg.Timeout = 10;
 * cfg.ServerName = 'ldap.internal.acme.com';
 * // optional config can be passed as third argument
 * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com', cfg);
 * ```
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
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const users = client.FindADObjects(ldap.FilterIsPerson);
    * log(to_json(users));
    * ```
    */
    public FindADObjects(filter: string): SearchResult | null {
        return null;
    }
    

    /**
    * GetADUsers returns all AD users
    * using FilterIsPerson filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const users = client.GetADUsers();
    * log(to_json(users));
    * ```
    */
    public GetADUsers(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADActiveUsers returns all AD users
    * using FilterIsPerson and FilterAccountEnabled filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const users = client.GetADActiveUsers();
    * log(to_json(users));
    * ```
    */
    public GetADActiveUsers(): SearchResult | null {
        return null;
    }
    

    /**
    * GetAdUserWithNeverExpiringPasswords returns all AD users
    * using FilterIsPerson and FilterDontExpirePassword filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const users = client.GetADUserWithNeverExpiringPasswords();
    * log(to_json(users));
    * ```
    */
    public GetADUserWithNeverExpiringPasswords(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADUserTrustedForDelegation returns all AD users that are trusted for delegation
    * using FilterIsPerson and FilterTrustedForDelegation filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const users = client.GetADUserTrustedForDelegation();
    * log(to_json(users));
    * ```
    */
    public GetADUserTrustedForDelegation(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADUserWithPasswordNotRequired returns all AD users that do not require a password
    * using FilterIsPerson and FilterPasswordNotRequired filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const users = client.GetADUserWithPasswordNotRequired();
    * log(to_json(users));
    * ```
    */
    public GetADUserWithPasswordNotRequired(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADGroups returns all AD groups
    * using FilterIsGroup filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const groups = client.GetADGroups();
    * log(to_json(groups));
    * ```
    */
    public GetADGroups(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADDCList returns all AD domain controllers
    * using FilterIsComputer, FilterAccountEnabled and FilterServerTrustAccount filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const dcs = client.GetADDCList();
    * log(to_json(dcs));
    * ```
    */
    public GetADDCList(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADAdmins returns all AD admins
    * using FilterIsPerson, FilterAccountEnabled and FilterIsAdmin filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const admins = client.GetADAdmins();
    * log(to_json(admins));
    * ```
    */
    public GetADAdmins(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADUserKerberoastable returns all AD users that are kerberoastable
    * using FilterIsPerson, FilterAccountEnabled and FilterHasServicePrincipalName filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const kerberoastable = client.GetADUserKerberoastable();
    * log(to_json(kerberoastable));
    * ```
    */
    public GetADUserKerberoastable(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADUserAsRepRoastable returns all AD users that are AsRepRoastable
    * using FilterIsPerson, and FilterDontRequirePreauth filter query
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const AsRepRoastable = client.GetADUserAsRepRoastable();
    * log(to_json(AsRepRoastable));
    * ```
    */
    public GetADUserAsRepRoastable(): SearchResult | null {
        return null;
    }
    

    /**
    * GetADDomainSID returns the SID of the AD domain
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const domainSID = client.GetADDomainSID();
    * log(domainSID);
    * ```
    */
    public GetADDomainSID(): string {
        return "";
    }
    

    /**
    * Authenticate authenticates with the ldap server using the given username and password
    * performs NTLMBind first and then Bind/UnauthenticatedBind if NTLMBind fails
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * client.Authenticate('user', 'password');
    * ```
    */
    public Authenticate(username: string): void {
        return;
    }
    

    /**
    * AuthenticateWithNTLMHash authenticates with the ldap server using the given username and NTLM hash
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * client.AuthenticateWithNTLMHash('pdtm', 'hash');
    * ```
    */
    public AuthenticateWithNTLMHash(username: string): void {
        return;
    }
    

    /**
    * Search accepts whatever filter and returns a list of maps having provided attributes
    * as keys and associated values mirroring the ones returned by ldap
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const results = client.Search('(objectClass=*)', 'cn', 'mail');
    * ```
    */
    public Search(filter: string, attributes: any): SearchResult | null {
        return null;
    }
    

    /**
    * AdvancedSearch accepts all values of search request type and return Ldap Entry
    * its up to user to handle the response
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const results = client.AdvancedSearch(ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, '(objectClass=*)', ['cn', 'mail'], []);
    * ```
    */
    public AdvancedSearch(Scope: number, TypesOnly: boolean, Filter: string, Attributes: string[], Controls: any): SearchResult | null {
        return null;
    }
    

    /**
    * CollectLdapMetadata collects metadata from ldap server.
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * const metadata = client.CollectMetadata();
    * log(to_json(metadata));
    * ```
    */
    public CollectMetadata(): Metadata | null {
        return null;
    }
    

    /**
    * close the ldap connection
    * @example
    * ```javascript
    * const ldap = require('nuclei/ldap');
    * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
    * client.Close();
    * ```
    */
    public Close(): void {
        return;
    }
    

}



/**
 * Config is extra configuration for the ldap client
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * const cfg = new ldap.Config();
 * cfg.Timeout = 10;
 * cfg.ServerName = 'ldap.internal.acme.com';
 * cfg.Upgrade = true; // upgrade to tls
 * ```
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
 * LdapAttributes represents all LDAP attributes of a particular
 * ldap entry
 */
export interface LdapAttributes {
    
    /**
    * CurrentTime contains current time
    */
    
    CurrentTime?: string[],
    
    /**
    * SubschemaSubentry contains subschema subentry
    */
    
    SubschemaSubentry?: string[],
    
    /**
    * DsServiceName contains ds service name
    */
    
    DsServiceName?: string[],
    
    /**
    * NamingContexts contains naming contexts
    */
    
    NamingContexts?: string[],
    
    /**
    * DefaultNamingContext contains default naming context
    */
    
    DefaultNamingContext?: string[],
    
    /**
    * SchemaNamingContext contains schema naming context
    */
    
    SchemaNamingContext?: string[],
    
    /**
    * ConfigurationNamingContext contains configuration naming context
    */
    
    ConfigurationNamingContext?: string[],
    
    /**
    * RootDomainNamingContext contains root domain naming context
    */
    
    RootDomainNamingContext?: string[],
    
    /**
    * SupportedLDAPVersion contains supported LDAP version
    */
    
    SupportedLDAPVersion?: string[],
    
    /**
    * HighestCommittedUSN contains highest committed USN
    */
    
    HighestCommittedUSN?: string[],
    
    /**
    * SupportedSASLMechanisms contains supported SASL mechanisms
    */
    
    SupportedSASLMechanisms?: string[],
    
    /**
    * DnsHostName contains DNS host name
    */
    
    DnsHostName?: string[],
    
    /**
    * LdapServiceName contains LDAP service name
    */
    
    LdapServiceName?: string[],
    
    /**
    * ServerName contains server name
    */
    
    ServerName?: string[],
    
    /**
    * IsSynchronized contains is synchronized
    */
    
    IsSynchronized?: string[],
    
    /**
    * IsGlobalCatalogReady contains is global catalog ready
    */
    
    IsGlobalCatalogReady?: string[],
    
    /**
    * DomainFunctionality contains domain functionality
    */
    
    DomainFunctionality?: string[],
    
    /**
    * ForestFunctionality contains forest functionality
    */
    
    ForestFunctionality?: string[],
    
    /**
    * DomainControllerFunctionality contains domain controller functionality
    */
    
    DomainControllerFunctionality?: string[],
    
    /**
    * DistinguishedName contains the distinguished name
    */
    
    DistinguishedName?: string[],
    
    /**
    * SAMAccountName contains the SAM account name
    */
    
    SAMAccountName?: string[],
    
    /**
    * PWDLastSet contains the password last set time
    */
    
    PWDLastSet?: string[],
    
    /**
    * LastLogon contains the last logon time
    */
    
    LastLogon?: string[],
    
    /**
    * MemberOf contains the groups the entry is a member of
    */
    
    MemberOf?: string[],
    
    /**
    * ServicePrincipalName contains the service principal names
    */
    
    ServicePrincipalName?: string[],
    
    /**
    * Extra contains other extra fields which might be present
    */
    
    Extra?: Record<string, any>,
}



/**
 * LdapEntry represents a single LDAP entry
 */
export interface LdapEntry {
    
    /**
    * DN contains distinguished name
    */
    
    DN?: string,
    
    /**
    * Attributes contains list of attributes
    */
    
    Attributes?: LdapAttributes,
}



/**
 * Metadata is the metadata for ldap server.
 * this is returned by CollectMetadata method
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
 * SearchResult contains search result of any / all ldap search request
 * @example
 * ```javascript
 * const ldap = require('nuclei/ldap');
 * const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
 * const results = client.Search('(objectinterface=*)', 'cn', 'mail');
 * ```
 */
export interface SearchResult {
    
    /**
    * Referrals contains list of referrals
    */
    
    Referrals?: string[],
    
    /**
    * Controls contains list of controls
    */
    
    Controls?: string[],
    
    /**
    * Entries contains list of entries
    */
    
    Entries?: LdapEntry[],
}

