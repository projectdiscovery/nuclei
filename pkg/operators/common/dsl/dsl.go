package dsl

import (
	"fmt"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns/dnsclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	HelperFunctions map[string]govaluate.ExpressionFunction
	FunctionNames   []string
	// knownPorts is a list of known ports for protocols implemented in nuclei
	knowPorts = []string{"80", "443", "8080", "8081", "8443", "53"}
)

func init() {
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("resolve", []string{
		"(host string) string",
		"(format string) string",
	}, false, func(args ...interface{}) (interface{}, error) {
		argCount := len(args)
		if argCount == 0 || argCount > 2 {
			return nil, dsl.ErrInvalidDslFunction
		}
		format := "4"
		var dnsType uint16
		if len(args) > 1 {
			format = strings.ToLower(types.ToString(args[1]))
		}

		switch format {
		case "4", "a":
			dnsType = dns.TypeA
		case "6", "aaaa":
			dnsType = dns.TypeAAAA
		case "cname":
			dnsType = dns.TypeCNAME
		case "ns":
			dnsType = dns.TypeNS
		case "txt":
			dnsType = dns.TypeTXT
		case "srv":
			dnsType = dns.TypeSRV
		case "ptr":
			dnsType = dns.TypePTR
		case "mx":
			dnsType = dns.TypeMX
		case "soa":
			dnsType = dns.TypeSOA
		case "caa":
			dnsType = dns.TypeCAA
		default:
			return nil, fmt.Errorf("invalid dns type")
		}

		err := dnsclientpool.Init(&types.Options{})
		if err != nil {
			return nil, err
		}
		dnsClient, err := dnsclientpool.Get(nil, &dnsclientpool.Configuration{})
		if err != nil {
			return nil, err
		}

		// query
		rawResp, err := dnsClient.Query(types.ToString(args[0]), dnsType)
		if err != nil {
			return nil, err
		}

		dnsValues := map[uint16][]string{
			dns.TypeA:     rawResp.A,
			dns.TypeAAAA:  rawResp.AAAA,
			dns.TypeCNAME: rawResp.CNAME,
			dns.TypeNS:    rawResp.NS,
			dns.TypeTXT:   rawResp.TXT,
			dns.TypeSRV:   rawResp.SRV,
			dns.TypePTR:   rawResp.PTR,
			dns.TypeMX:    rawResp.MX,
			dns.TypeCAA:   rawResp.CAA,
			dns.TypeSOA:   rawResp.GetSOARecords(),
		}

		if values, ok := dnsValues[dnsType]; ok {
			firstFound, found := sliceutil.FirstNonZero(values)
			if found {
				return firstFound, nil
			}
		}

		return "", fmt.Errorf("no records found")
	}))
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("getNetworkPort", []string{
		"(Port string,defaultPort string) string)",
		"(Port int,defaultPort int) int",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, dsl.ErrInvalidDslFunction
		}
		port := types.ToString(args[0])
		defaultPort := types.ToString(args[1])
		if port == "" || stringsutil.EqualFoldAny(port, knowPorts...) {
			return defaultPort, nil
		}
		return port, nil
	}))

	dsl.PrintDebugCallback = func(args ...interface{}) error {
		gologger.Info().Msgf("print_debug value: %s", fmt.Sprint(args))
		return nil
	}

	HelperFunctions = dsl.HelperFunctions()
	FunctionNames = dsl.GetFunctionNames(HelperFunctions)
}

type CompilationError struct {
	DslSignature string
	WrappedError error
}

func (e *CompilationError) Error() string {
	return fmt.Sprintf("could not compile DSL expression %q: %v", e.DslSignature, e.WrappedError)
}

func (e *CompilationError) Unwrap() error {
	return e.WrappedError
}

func GetPrintableDslFunctionSignatures(noColor bool) string {
	return dsl.GetPrintableDslFunctionSignatures(noColor)
}
