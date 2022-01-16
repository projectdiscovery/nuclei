package file

import (
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// Request contains a File matching mechanism for local disk operations.
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`
	// description: |
	//   Extensions is the list of extensions to perform matching on.
	// examples:
	//   - value: '[]string{".txt", ".go", ".json"}'
	Extensions []string `yaml:"extensions,omitempty" jsonschema:"title=extensions to match,description=List of extensions to perform matching on"`
	// description: |
	//   DenyList is the list of file, directories or extensions to deny during matching.
	//
	//   By default, it contains some non-interesting extensions that are hardcoded
	//   in nuclei.
	// examples:
	//   - value: '[]string{".avi", ".mov", ".mp3"}'
	DenyList []string `yaml:"denylist,omitempty" jsonschema:"title=denylist, directories and extentions to deny match,description=List of files, directories and extensions to deny during matching"`

	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" jsonschema:"title=id of the request,description=ID is the optional ID for the request"`

	// description: |
	//   MaxSize is the maximum size of the file to run request on.
	//
	//   By default, nuclei will process 5 MB files and not go more than that.
	//   It can be set to much lower or higher depending on use.
	// examples:
	//   - value: 2048
	MaxSize           int                  `yaml:"max-size,omitempty" jsonschema:"title=max size data to run request on,description=Maximum size of the file to run request on"`
	CompiledOperators *operators.Operators `yaml:"-"`

	// cache any variables that may be needed for operation.
	options    *protocols.ExecuterOptions
	extensions map[string]struct{}
	denyList   map[string]struct{}

	// description: |
	//   NoRecursive specifies whether to not do recursive checks if folders are provided.
	NoRecursive bool `yaml:"no-recursive,omitempty" jsonschema:"title=do not perform recursion,description=Specifies whether to not do recursive checks if folders are provided"`

	allExtensions bool
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"template-id":       "ID of the template executed",
	"template-info":     "Info Block of the template executed",
	"template-path":     "Path of the template executed",
	"matched":           "Matched is the input which was matched upon",
	"path":              "Path is the path of file on local filesystem",
	"type":              "Type is the type of request made",
	"raw,body,all,data": "Raw contains the raw file contents",
}

// defaultDenylist is the default list of extensions to be denied
var defaultDenylist = []string{".3g2", ".3gp", ".7z", ".apk", ".arj", ".avi", ".axd", ".bmp", ".css", ".csv", ".deb", ".dll", ".doc", ".drv", ".eot", ".exe", ".flv", ".gif", ".gifv", ".gz", ".h264", ".ico", ".iso", ".jar", ".jpeg", ".jpg", ".lock", ".m4a", ".m4v", ".map", ".mkv", ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".msi", ".ogg", ".ogm", ".ogv", ".otf", ".pdf", ".pkg", ".png", ".ppt", ".psd", ".rar", ".rm", ".rpm", ".svg", ".swf", ".sys", ".tar.gz", ".tar", ".tif", ".tiff", ".ttf", ".vob", ".wav", ".webm", ".wmv", ".woff", ".woff2", ".xcf", ".xls", ".xlsx", ".zip"}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return request.ID
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecuterOptions) error {
	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.CompiledOperators = compiled
	}
	// By default, use 5 MB as max size to read.
	if request.MaxSize == 0 {
		request.MaxSize = 5 * 1024 * 1024
	}
	request.options = options

	request.extensions = make(map[string]struct{})
	request.denyList = make(map[string]struct{})

	for _, extension := range request.Extensions {
		if extension == "all" {
			request.allExtensions = true
		} else {
			if !strings.HasPrefix(extension, ".") {
				extension = "." + extension
			}
			request.extensions[extension] = struct{}{}
		}
	}
	// process default denylist (extensions)
	for _, excludeItem := range defaultDenylist {
		if !strings.HasPrefix(excludeItem, ".") {
			excludeItem = "." + excludeItem
		}
		request.denyList[excludeItem] = struct{}{}
	}
	for _, excludeItem := range request.DenyList {
		request.denyList[excludeItem] = struct{}{}
		// also add a cleaned version as the exclusion path can be dirty (eg. /a/b/c, /a/b/c/, a///b///c/../d)
		request.denyList[filepath.Clean(excludeItem)] = struct{}{}
	}
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	return 0
}
