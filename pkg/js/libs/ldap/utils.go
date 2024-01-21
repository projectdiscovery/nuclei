package ldap

import (
	"fmt"
	"strings"
)

func DecodeSID(s string) string {
	b := []byte(s)
	revisionLvl := int(b[0])
	subAuthorityCount := int(b[1]) & 0xFF

	var authority int
	for i := 2; i <= 7; i++ {
		authority = authority | int(b[i])<<(8*(5-(i-2)))
	}

	var size = 4
	var offset = 8
	var subAuthorities []int
	for i := 0; i < subAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		subAuthorities = append(subAuthorities, subAuthority)
		offset += size
	}

	var builder strings.Builder
	builder.WriteString("S-")
	builder.WriteString(fmt.Sprintf("%d-", revisionLvl))
	builder.WriteString(fmt.Sprintf("%d", authority))
	for _, v := range subAuthorities {
		builder.WriteString(fmt.Sprintf("-%d", v))
	}
	return builder.String()
}
