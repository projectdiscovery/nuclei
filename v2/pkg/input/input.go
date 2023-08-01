package input

import (
	"net"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/hmap/store/hybrid"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/projectdiscovery/utils/ports"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

// Helper is a structure for helping with input transformation
type Helper struct {
	InputsHTTP *hybrid.HybridMap
}

// NewHelper returns a new input helper instance
func NewHelper() *Helper {
	helper := &Helper{}
	return helper
}

// Close closes the resources associated with input helper
func (h *Helper) Close() error {
	var err error
	if h.InputsHTTP != nil {
		err = h.InputsHTTP.Close()
	}
	return err
}

// Transform transforms an input based on protocol type and returns
// appropriate input based on it.
func (h *Helper) Transform(input string, protocol templateTypes.ProtocolType) string {
	switch protocol {
	case templateTypes.DNSProtocol, templateTypes.WHOISProtocol:
		return h.convertInputToType(input, typeHostOnly, "")
	case templateTypes.FileProtocol, templateTypes.OfflineHTTPProtocol:
		return h.convertInputToType(input, typeFilepath, "")
	case templateTypes.HTTPProtocol, templateTypes.HeadlessProtocol:
		return h.convertInputToType(input, typeURL, "")
	case templateTypes.NetworkProtocol:
		return h.convertInputToType(input, typeHostWithOptionalPort, "")
	case templateTypes.WebsocketProtocol:
		return h.convertInputToType(input, typeWebsocket, "")
	}
	return input
}

type inputType int

const (
	typeHostOnly inputType = iota + 1
	typeHostWithPort
	typeHostWithOptionalPort
	typeURL
	typeFilepath
	typeWebsocket
)

// convertInputToType converts an input based on an inputType.
// Various formats are supported for inputs and their transformation
func (h *Helper) convertInputToType(input string, inputType inputType, defaultPort string) string {
	isURL := strings.Contains(input, "://")
	uri, _ := urlutil.Parse(input)

	var host, port string
	if isURL && uri != nil {
		host, port, _ = net.SplitHostPort(uri.Host)
	} else {
		host, port, _ = net.SplitHostPort(input)
	}

	hasHost := host != ""
	hasPort := ports.IsValid(port)
	hasDefaultPort := ports.IsValid(defaultPort)

	switch inputType {
	case typeFilepath:
		// if it has ports most likely it's not a file
		if hasPort {
			return ""
		}
		if filepath.IsAbs(input) {
			return input
		}
		if absPath, _ := filepath.Abs(input); absPath != "" && fileutil.FileOrFolderExists(absPath) {
			return input
		}
		if _, err := filepath.Match(input, ""); err != filepath.ErrBadPattern && !isURL {
			return input
		}
	case typeHostOnly:
		if hasHost {
			return host
		}
		if isURL && uri != nil {
			return uri.Hostname()
		}
		return input
	case typeURL:
		if uri != nil && stringsutil.EqualFoldAny(uri.Scheme, "http", "https") {
			return input
		}
		if h.InputsHTTP != nil {
			if probed, ok := h.InputsHTTP.Get(input); ok {
				return string(probed)
			}
		}
	case typeHostWithPort, typeHostWithOptionalPort:
		if hasHost && hasPort {
			return net.JoinHostPort(host, port)
		}
		if uri != nil && !hasPort && uri.Scheme == "https" {
			return net.JoinHostPort(uri.Host, "443")
		}
		if hasDefaultPort {
			return net.JoinHostPort(input, defaultPort)
		}
		if inputType == typeHostWithOptionalPort {
			return input
		}
	case typeWebsocket:
		if uri != nil && stringsutil.EqualFoldAny(uri.Scheme, "ws", "wss") {
			return input
		}
	}
	return ""
}
