package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

type ADObject struct {
	DistinguishedName    string
	SAMAccountName       string
	PWDLastSet           string
	LastLogon            string
	MemberOf             []string
	ServicePrincipalName []string
}

func (c *LdapClient) FindADObjects(filter string) ([]ADObject, error) {
	sr := ldap.NewSearchRequest(
		c.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{
			"distinguishedName",
			"sAMAccountName",
			"pwdLastSet",
			"lastLogon",
			"memberOf",
			"servicePrincipalName",
		},
		nil,
	)

	res, err := c.Conn.Search(sr)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no object returned from query")
	}

	var objects []ADObject
	for _, obj := range res.Entries {
		objects = append(objects, ADObject{
			DistinguishedName:    obj.GetAttributeValue("distinguishedName"),
			SAMAccountName:       obj.GetAttributeValue("sAMAccountName"),
			PWDLastSet:           obj.GetAttributeValue("pwdLastSet"),
			LastLogon:            obj.GetAttributeValue("lastLogon"),
			MemberOf:             obj.GetAttributeValues("memberOf"),
			ServicePrincipalName: obj.GetAttributeValues("servicePrincipalName"),
		})
	}
	return objects, nil
}
