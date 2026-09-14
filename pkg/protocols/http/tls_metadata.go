package http

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// tlsVersionToString mirrors tlsx naming so HTTP and SSL protocol fields align.
var tlsVersionToString = map[uint16]string{
	tls.VersionTLS10: "tls10",
	tls.VersionTLS11: "tls11",
	tls.VersionTLS12: "tls12",
	tls.VersionTLS13: "tls13",
}

// enrichEventWithTLSMetadata copies TLS handshake / leaf-certificate fields from
// the HTTP response into the DSL event using the same names as the ssl protocol.
// Revocation / trust-store checks are intentionally skipped to avoid network
// side effects on every HTTPS request.
func enrichEventWithTLSMetadata(data output.InternalEvent, resp *http.Response) {
	if data == nil || resp == nil || resp.TLS == nil {
		return
	}
	state := resp.TLS

	if ver, ok := tlsVersionToString[state.Version]; ok {
		data["tls_version"] = ver
	}
	if cipher := tls.CipherSuiteName(state.CipherSuite); cipher != "" {
		data["cipher"] = cipher
	}
	if state.ServerName != "" {
		data["sni"] = state.ServerName
	}
	if len(state.PeerCertificates) == 0 {
		return
	}

	cert := state.PeerCertificates[0]
	domainNames := append([]string{cert.Subject.CommonName}, cert.DNSNames...)

	data["not_before"] = cert.NotBefore
	data["not_after"] = cert.NotAfter
	data["expired"] = clients.IsExpired(cert.NotAfter)
	data["self_signed"] = clients.IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId, cert.DNSNames)
	if state.ServerName != "" {
		data["mismatched"] = clients.IsMisMatchedCert(state.ServerName, domainNames)
	}
	data["subject_dn"] = cert.Subject.String()
	data["subject_cn"] = cert.Subject.CommonName
	if len(cert.Subject.Organization) > 0 {
		data["subject_org"] = cert.Subject.Organization
	}
	if len(cert.DNSNames) > 0 {
		data["subject_an"] = cert.DNSNames
	}
	if len(cert.EmailAddresses) > 0 {
		data["emails"] = cert.EmailAddresses
	}
	data["issuer_dn"] = cert.Issuer.String()
	data["issuer_cn"] = cert.Issuer.CommonName
	if len(cert.Issuer.Organization) > 0 {
		data["issuer_org"] = cert.Issuer.Organization
	}
	if serial := clients.FormatToSerialNumber(cert.SerialNumber); serial != "" {
		data["serial"] = serial
	}
	data["fingerprint_hash"] = map[string]string{
		"md5":    clients.MD5Fingerprint(cert.Raw),
		"sha1":   clients.SHA1Fingerprint(cert.Raw),
		"sha256": clients.SHA256Fingerprint(cert.Raw),
	}
	data["wildcard_certificate"] = clients.IsWildCardCert(domainNames)

	domains := make([]string, 0, len(domainNames))
	seen := make(map[string]struct{}, len(domainNames))
	for _, d := range domainNames {
		d = strings.TrimPrefix(d, "*.")
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
	}
	if len(domains) > 0 {
		data["domains"] = domains
	}
}
