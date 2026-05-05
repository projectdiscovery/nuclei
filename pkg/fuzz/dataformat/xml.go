package dataformat

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/clbanning/mxj/v2"
)

// XML is an XML encoder
type XML struct{}

// NewXML returns a new XML encoder
func NewXML() *XML {
	return &XML{}
}

// IsType returns true if the data is XML encoded
func (x *XML) IsType(data string) bool {
	return strings.HasPrefix(data, "<") && strings.HasSuffix(data, ">")
}

// Encode encodes the data into XML format
func (x *XML) Encode(data KV) (string, error) {
	var header string
	if value := data.Get("#_xml_header"); value != nil {
		header = value.(string)
		data.Delete("#_xml_header")
	}
	marshalled, err := mxj.Map(data.Map).Xml()
	if err != nil {
		return "", err
	}
	if header != "" {
		return fmt.Sprintf("<?%s?>%s", header, string(marshalled)), nil
	}
	return string(marshalled), err
}

var xmlHeader = regexp.MustCompile(`\<\?(.*)\?\>`)

// Decode decodes the data from XML format
func (x *XML) Decode(data string) (KV, error) {
	var prefixStr string
	prefix := xmlHeader.FindAllStringSubmatch(data, -1)
	if len(prefix) > 0 {
		prefixStr = prefix[0][1]
	}

	decoded, err := mxj.NewMapXml([]byte(data))
	if err != nil {
		return KV{}, err
	}
	decoded["#_xml_header"] = prefixStr
	return KVMap(decoded), nil
}

// Name returns the name of the encoder
func (x *XML) Name() string {
	return XMLDataFormat
}
