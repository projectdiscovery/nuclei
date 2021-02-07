package file

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// Request contains a File matching mechanism for local disk operations.
type Request struct {
	ID string `yaml:"id"`

	// MaxSize is the maximum size of the file to run request on.
	// By default, nuclei will process 5MB files and not go more than that.
	// It can be set to much lower or higher depending on use.
	MaxSize int `yaml:"max-size"`
	// NoRecursive specifies whether to not do recursive checks if folders are provided.
	NoRecursive bool `yaml:"no-recursive"`
	// Extensions is the list of extensions to perform matching on.
	Extensions []string `yaml:"extensions"`
	// ExtensionDenylist is the list of file extensions to deny during matching.
	ExtensionDenylist []string `yaml:"denylist"`

	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`
	CompiledOperators   *operators.Operators

	// cache any variables that may be needed for operation.
	options           *protocols.ExecuterOptions
	extensions        map[string]struct{}
	allExtensions     bool
	extensionDenylist map[string]struct{}
}

// defaultDenylist is the default list of extensions to be denied
var defaultDenylist = []string{".3g2", ".3gp", ".7z", ".apk", ".arj", ".avi", ".axd", ".bmp", ".css", ".csv", ".deb", ".dll", ".doc", ".drv", ".eot", ".exe", ".flv", ".gif", ".gifv", ".gz", ".h264", ".ico", ".iso", ".jar", ".jpeg", ".jpg", ".lock", ".m4a", ".m4v", ".map", ".mkv", ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".msi", ".ogg", ".ogm", ".ogv", ".otf", ".pdf", ".pkg", ".png", ".ppt", ".psd", ".rar", ".rm", ".rpm", ".svg", ".swf", ".sys", ".tar.gz", ".tar", ".tif", ".tiff", ".ttf", ".txt", ".vob", ".wav", ".webm", ".wmv", ".woff", ".woff2", ".xcf", ".xls", ".xlsx", ".zip"}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	// By default use 5mb as max size to read.
	if r.MaxSize == 0 {
		r.MaxSize = 5 * 1024 * 1024
	}
	r.options = options

	r.extensions = make(map[string]struct{})
	r.extensionDenylist = make(map[string]struct{})

	for _, extension := range r.Extensions {
		if extension == "*" {
			r.allExtensions = true
		} else {
			r.extensions[extension] = struct{}{}
		}
	}
	for _, extension := range defaultDenylist {
		r.extensionDenylist[extension] = struct{}{}
	}
	for _, extension := range r.ExtensionDenylist {
		r.extensionDenylist[extension] = struct{}{}
	}
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	return 1
}
