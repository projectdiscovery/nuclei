package dsl

import (
	"errors"
	"fmt"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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
		return nil, errors.New("deprecated - use js protocol")
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
