package formats

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/retryablehttp-go"
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
	// VarsTextTemplating uses Variables and inject it into the input
	// this is used for text templating of variables based on carvel ytt
	// Only available for Yaml formats
	VarsTextTemplating bool
	// VarsFilePaths is the path to the file containing variables
	VarsFilePaths []string
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

// SpecDownloader is an interface for downloading API specifications from URLs
type SpecDownloader interface {
	// Download downloads the spec from the given URL and saves it to tmpDir
	// Returns the path to the downloaded file
	// httpClient is a retryablehttp.Client instance (can be nil for fallback)
	Download(url, tmpDir string, httpClient *retryablehttp.Client) (string, error)
	// SupportedExtensions returns the list of supported file extensions
	SupportedExtensions() []string
}

var (
	DefaultVarDumpFileName = "required_openapi_params.yaml"
	ErrNoVarsDumpFile      = errors.New("no required params file found")
	MaxVarDumpFileSize     int64 = 8 * 1024 * 1024 // 8MB limit for dump file
	MaxSpecFileSize        int64 = 8 * 1024 * 1024 // 8MB limit for spec files
	ErrFileTooLarge        = errors.New("file size exceeds maximum allowed limit")
)

// ReadLimitedFile reads at most maxSize bytes from the file at path.
// If the file exceeds maxSize, it returns an error without buffering the entire file.
func ReadLimitedFile(path string, maxSize int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file %q exceeds maximum allowed size (%d bytes): %w", path, maxSize, ErrFileTooLarge)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file %q exceeds maximum allowed size (%d bytes): %w", path, maxSize, ErrFileTooLarge)
	}
	return data, nil
}

// ReadLimited reads at most maxSize bytes from r.
// If r provides more than maxSize bytes, it returns an error.
func ReadLimited(r io.Reader, maxSize int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("input exceeds maximum allowed size (%d bytes): %w", maxSize, ErrFileTooLarge)
	}
	return data, nil
}

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
	bin, err := ReadLimitedFile(DefaultVarDumpFileName, MaxVarDumpFileSize)
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
	defer func() {
		_ = f.Close()
	}()
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
