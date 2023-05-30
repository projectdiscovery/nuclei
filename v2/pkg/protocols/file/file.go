package file

import (
	"path/filepath"
	"strings"

	"github.com/docker/go-units"
	"github.com/h2non/filetype"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

var (
	defaultMaxReadSize, _ = units.FromHumanSize("1Gb")
	chunkSize, _          = units.FromHumanSize("100Mb")
)

// Request contains a File matching mechanism for local disk operations.
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline"`
	// description: |
	//   Extensions is the list of extensions or mime types to perform matching on.
	// examples:
	//   - value: '[]string{".txt", ".go", ".json"}'
	Extensions []string `yaml:"extensions,omitempty" json:"extensions,omitempty" jsonschema:"title=extensions to match,description=List of extensions to perform matching on"`
	// description: |
	//   DenyList is the list of file, directories, mime types or extensions to deny during matching.
	//
	//   By default, it contains some non-interesting extensions that are hardcoded
	//   in nuclei.
	// examples:
	//   - value: '[]string{".avi", ".mov", ".mp3"}'
	DenyList []string `yaml:"denylist,omitempty" json:"denylist,omitempty" jsonschema:"title=denylist, directories and extensions to deny match,description=List of files, directories and extensions to deny during matching"`

	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the request,description=ID is the optional ID for the request"`

	// description: |
	//   MaxSize is the maximum size of the file to run request on.
	//
	//   By default, nuclei will process 1 GB of content and not go more than that.
	//   It can be set to much lower or higher depending on use.
	//   If set to "no" then all content will be processed
	// examples:
	//   - value: "\"5Mb\""
	MaxSize string `yaml:"max-size,omitempty" json:"max-size,omitempty" jsonschema:"title=max size data to run request on,description=Maximum size of the file to run request on"`
	maxSize int64

	// description: |
	//   elaborates archives
	Archive bool `yaml:"archive,omitempty" json:"archive,omitempty" jsonschema:"title=enable archives,description=Process compressed archives without unpacking"`

	// description: |
	//   enables mime types check
	MimeType bool `yaml:"mime-type,omitempty" json:"mime-type,omitempty" jsonschema:"title=enable filtering by mime-type,description=Filter files by mime-type"`

	CompiledOperators *operators.Operators `yaml:"-" json:"-"`

	// cache any variables that may be needed for operation.
	options             *protocols.ExecutorOptions
	mimeTypesChecks     []string
	extensions          map[string]struct{}
	denyList            map[string]struct{}
	denyMimeTypesChecks []string

	// description: |
	//   NoRecursive specifies whether to not do recursive checks if folders are provided.
	NoRecursive bool `yaml:"no-recursive,omitempty" json:"no-recursive,omitempty" jsonschema:"title=do not perform recursion,description=Specifies whether to not do recursive checks if folders are provided"`

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

// defaultDenylist contains common extensions to exclude
var defaultDenylist = []string{".3g2", ".3gp", ".arj", ".avi", ".axd", ".bmp", ".css", ".csv", ".deb", ".dll", ".doc", ".drv", ".eot", ".exe", ".flv", ".gif", ".gifv", ".h264", ".ico", ".iso", ".jar", ".jpeg", ".jpg", ".lock", ".m4a", ".m4v", ".map", ".mkv", ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".msi", ".ogg", ".ogm", ".ogv", ".otf", ".pdf", ".pkg", ".png", ".ppt", ".psd", ".rm", ".rpm", ".svg", ".swf", ".sys", ".tif", ".tiff", ".ttf", ".vob", ".wav", ".webm", ".wmv", ".woff", ".woff2", ".xcf", ".xls", ".xlsx"}

// defaultArchiveDenyList contains common archive extensions to exclude
var defaultArchiveDenyList = []string{".7z", ".apk", ".gz", ".rar", ".tar.gz", ".tar", ".zip"}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return request.ID
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	// if there are no matchers/extractors, we trigger an error as no operation would be performed on the template
	if request.Operators.IsEmpty() {
		return errors.New("empty operators")
	}
	compiled := &request.Operators
	compiled.ExcludeMatchers = options.ExcludeMatchers
	compiled.TemplateID = options.TemplateID
	if err := compiled.Compile(); err != nil {
		return errors.Wrap(err, "could not compile operators")
	}
	request.CompiledOperators = compiled

	// By default, use default max size if not defined
	switch {
	case request.MaxSize != "":
		maxSize, err := units.FromHumanSize(request.MaxSize)
		if err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.maxSize = maxSize
	case request.MaxSize == "no":
		request.maxSize = -1
	default:
		request.maxSize = defaultMaxReadSize
	}

	request.options = options

	request.extensions = make(map[string]struct{})
	request.denyList = make(map[string]struct{})

	for _, extension := range request.Extensions {
		switch {
		case extension == "all":
			request.allExtensions = true
		case request.MimeType && filetype.IsMIMESupported(extension):
			continue
		default:
			if !strings.HasPrefix(extension, ".") {
				extension = "." + extension
			}
			request.extensions[extension] = struct{}{}
		}
	}
	request.mimeTypesChecks = extractMimeTypes(request.Extensions)

	// process default denylist (extensions)
	var denyList []string
	if !request.Archive {
		denyList = append(defaultDenylist, defaultArchiveDenyList...)
	} else {
		denyList = defaultDenylist
	}
	for _, excludeItem := range denyList {
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
	request.denyMimeTypesChecks = extractMimeTypes(request.DenyList)
	return nil
}

func matchAnyMimeTypes(data []byte, mimeTypes []string) bool {
	for _, mimeType := range mimeTypes {
		if filetype.Is(data, mimeType) {
			return true
		}
	}
	return false
}

func extractMimeTypes(m []string) []string {
	var mimeTypes []string
	for _, mm := range m {
		if !filetype.IsMIMESupported(mm) {
			continue
		}
		mimeTypes = append(mimeTypes, mm)
	}
	return mimeTypes
}

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	return 0
}
