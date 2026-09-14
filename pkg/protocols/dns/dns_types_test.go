package dns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestToDNSRequestTypesDNSSEC(t *testing.T) {
	tests := []struct {
		input    string
		expected DNSRequestType
	}{
		{"NSEC", NSEC},
		{"nsec", NSEC},
		{"NSEC3", NSEC3},
		{"NSEC3PARAM", NSEC3PARAM},
		{"DNSKEY", DNSKEY},
		{"RRSIG", RRSIG},
		{"rrsig", RRSIG},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := toDNSRequestTypes(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
			require.Equal(t, normalizeValue(tt.expected.String()), normalizeValue(tt.input))
		})
	}
}

func TestToDNSRequestTypesInvalid(t *testing.T) {
	_, err := toDNSRequestTypes("NOTAREALTYPE")
	require.Error(t, err)
}

func TestQuestionTypeToIntDNSSEC(t *testing.T) {
	tests := []struct {
		input    string
		expected uint16
	}{
		{"NSEC", dns.TypeNSEC},
		{"NSEC3", dns.TypeNSEC3},
		{"NSEC3PARAM", dns.TypeNSEC3PARAM},
		{"DNSKEY", dns.TypeDNSKEY},
		{"RRSIG", dns.TypeRRSIG},
		{"A", dns.TypeA},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			require.Equal(t, tt.expected, questionTypeToInt(tt.input))
		})
	}
}

func TestGetSupportedDNSRequestTypesIncludesDNSSEC(t *testing.T) {
	supported := GetSupportedDNSRequestTypes()
	require.Contains(t, supported, NSEC)
	require.Contains(t, supported, NSEC3)
	require.Contains(t, supported, NSEC3PARAM)
	require.Contains(t, supported, DNSKEY)
	require.Contains(t, supported, RRSIG)
}

func TestMakeDNSRequestNSECQuestion(t *testing.T) {
	recursion := false
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: NSEC},
		Name:        "{{FQDN}}",
		Class:       "inet",
		Recursion:   &recursion,
	}
	request.question = questionTypeToInt(request.RequestType.String())
	request.class = classToInt(request.Class)

	msg, err := request.Make("example.com", map[string]interface{}{"FQDN": "example.com"})
	require.NoError(t, err)
	require.Len(t, msg.Question, 1)
	require.Equal(t, dns.TypeNSEC, msg.Question[0].Qtype)
	require.Equal(t, "example.com.", msg.Question[0].Name)
}

func TestDNSRequestTypeHolderUnmarshalYAMLDNSSEC(t *testing.T) {
	var holder DNSRequestTypeHolder
	err := holder.UnmarshalYAML(func(v interface{}) error {
		*v.(*string) = "NSEC3"
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, NSEC3, holder.DNSRequestType)
}
