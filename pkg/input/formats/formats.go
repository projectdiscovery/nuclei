package formats

import (
	"errors"
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/yaml.v3"
)

// ParseReqRespCallback is a callback function for discovered raw requests
type ParseReqRespCallback func(rr *types.RequestResponse) bool

// InputFormatOptions contains options for the input
// this can be variables that can be passed or
// overrides or some other options
type InputFormatOptions struct {
	// Variables is list of variables that can be used
	// while generating requests in given format
	Variables map[string]interface{}
	// SkipFormatValidation is used to skip format validation
	// while debugging or testing if format is invalid then
	// requests are skipped instead of creating invalid requests
	SkipFormatValidation bool
	// RequiredOnly only uses required fields when generating requests
	// instead of all fields
	RequiredOnly bool
}

// Format is an interface implemented by all input formats
type Format interface {
	// Name returns the name of the format
	Name() string
	// Parse parses the input and calls the provided callback
	// function for each RawRequest it discovers.
	Parse(input string, resultsCb ParseReqRespCallback) error
	// SetOptions sets the options for the input format
	SetOptions(options InputFormatOptions)
}

var (
	DefaultVarDumpFileName = "required_openapi_vars.yaml"
	ErrNoVarsDumpFile      = errors.New("no vars dump file found")
)

// == OpenAPIVarDumpFile ==
// this file is meant to be used in CLI mode
// to be more interactive and user-friendly when
// running nuclei with openapi format

// OpenAPIVarDumpFile is the structure of the required vars dump file
type OpenAPIVarDumpFile struct {
	Var []string `yaml:"var"`
}

// ReadOpenAPIVarDumpFile reads the required vars dump file
func ReadOpenAPIVarDumpFile() (*OpenAPIVarDumpFile, error) {
	var vars OpenAPIVarDumpFile
	if !fileutil.FileExists(DefaultVarDumpFileName) {
		return nil, ErrNoVarsDumpFile
	}
	bin, err := os.ReadFile(DefaultVarDumpFileName)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(bin, &vars)
	if err != nil {
		return nil, err
	}
	return &vars, nil
}

// WriteOpenAPIVarDumpFile writes the required vars dump file
func WriteOpenAPIVarDumpFile(vars *OpenAPIVarDumpFile) error {
	bin, err := yaml.Marshal(vars)
	if err != nil {
		return err
	}
	err = os.WriteFile(DefaultVarDumpFileName, bin, 0644)
	if err != nil {
		return err
	}
	return nil
}
