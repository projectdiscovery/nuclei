package formats

import (
	"errors"
	"io"
	"os"
	"strings"

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
	Parse(input io.Reader, resultsCb ParseReqRespCallback, filePath string) error
	// SetOptions sets the options for the input format
	SetOptions(options InputFormatOptions)
}

var (
	DefaultVarDumpFileName = "required_openapi_params.yaml"
	ErrNoVarsDumpFile      = errors.New("no required params file found")
)

// == OpenAPIParamsCfgFile ==
// this file is meant to be used in CLI mode
// to be more interactive and user-friendly when
// running nuclei with openapi format

// OpenAPIParamsCfgFile is the structure of the required vars dump file
type OpenAPIParamsCfgFile struct {
	Var          []string `yaml:"var"`
	OptionalVars []string `yaml:"-"` // this will be written to the file as comments
}

// ReadOpenAPIVarDumpFile reads the required vars dump file
func ReadOpenAPIVarDumpFile() (*OpenAPIParamsCfgFile, error) {
	var vars OpenAPIParamsCfgFile
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
	filtered := []string{}
	for _, v := range vars.Var {
		v = strings.TrimSpace(v)
		if !strings.HasSuffix(v, "=") {
			filtered = append(filtered, v)
		}
	}
	vars.Var = filtered
	return &vars, nil
}

// WriteOpenAPIVarDumpFile writes the required vars dump file
func WriteOpenAPIVarDumpFile(vars *OpenAPIParamsCfgFile) error {
	f, err := os.OpenFile(DefaultVarDumpFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	bin, err := yaml.Marshal(vars)
	if err != nil {
		return err
	}
	_, _ = f.Write(bin)
	if len(vars.OptionalVars) > 0 {
		_, _ = f.WriteString("\n    # Optional parameters\n")
		for _, v := range vars.OptionalVars {
			_, _ = f.WriteString("    # - " + v + "=\n")
		}
	}
	return f.Sync()
}
