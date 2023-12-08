
/**
 * LdapClient Class
 */
export class LdapClient {
    

    /**
    * IsLdap checks if the given host and port are running ldap server.
    * @throws {Error} - if the operation fails
    */
    public IsLdap(host: string, port: number): boolean | null {
        return null;
    }
    

    /**
    * CollectLdapMetadata collects metadata from ldap server.
    * @throws {Error} - if the operation fails
    */
    public CollectLdapMetadata(domain: string, controller: string): LDAPMetadata | null {
        return null;
    }
    

}


/**
 * LDAPMetadata interface
 */
export interface LDAPMetadata {
    
    BaseDN?: string,
    
    Domain?: string,
    
    DefaultNamingContext?: string,
    
    DomainFunctionality?: string,
    
    ForestFunctionality?: string,
    
    DomainControllerFunctionality?: string,
    
    DnsHostName?: string,
}

