package formats

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
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
	ErrNoVarsDumpFile = errors.New("no required params file found")
)

// == OpenAPIParamsCfgFile ==
// this file is meant to be used in CLI mode
// to be more interactive and user-friendly when
// running nuclei with openapi format

// OpenAPIParamsCfgFile is the structure of the required vars dump file
type OpenAPIParamsCfgFile struct {
	FileName     string   `yaml:"-"`
	Var          []string `yaml:"var"`
	OptionalVars []string `yaml:"-"` // this will be written to the file as comments
}

// UpdateMissingVarsFile writes the required vars dump file
func UpdateMissingVarsFile(vars *OpenAPIParamsCfgFile) error {
	existing := make(map[string]string)
	if fileutil.FileExists(vars.FileName) {
		bin, err := os.ReadFile(vars.FileName)
		if err != nil {
			return err
		}
		for _, v := range strings.Split(string(bin), "\n") {
			v = strings.TrimSpace(v)
			parts := strings.Split(v, "=")
			if len(parts) == 1 {
				existing[parts[0]] = ""
			} else if len(parts) == 2 {
				existing[parts[0]] = parts[1]
			}
		}
	}
	// add missing vars to existing
	for _, v := range vars.Var {
		if _, ok := existing[v]; !ok {
			existing[v] = ""
		}
	}
	// add optional vars to existing
	for _, v := range vars.OptionalVars {
		if _, ok := existing[v]; !ok {
			existing[v] = ""
		}
	}
	f, err := os.OpenFile(vars.FileName, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, v := range mapsutil.GetSortedKeys(existing) {
		if strings.TrimSpace(v) == "" {
			continue
		}
		f.WriteString(fmt.Sprintf("%s=%s\n", v, existing[v]))
	}
	return nil
}
