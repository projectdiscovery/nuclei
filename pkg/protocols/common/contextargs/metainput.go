package contextargs

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"net"
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/segmentio/ksuid"
)

// MetaInput represents a target with metadata (TODO: replace with https://github.com/projectdiscovery/metainput)
type MetaInput struct {
	// Input represent the target
	Input string `json:"input,omitempty"`
	// CustomIP to use for connection
	CustomIP string `json:"customIP,omitempty"`
	// hash of the input
	hash string `json:"-"`

	// ReqResp is the raw request for the input
	ReqResp *types.RequestResponse `json:"raw-request,omitempty"`

	mu *sync.Mutex
}

func NewMetaInput() *MetaInput {
	return &MetaInput{mu: &sync.Mutex{}}
}

func (metaInput *MetaInput) marshalToBuffer() (bytes.Buffer, error) {
	var b bytes.Buffer
	err := jsoniter.NewEncoder(&b).Encode(metaInput)
	return b, err
}

// Target returns the target of the metainput
func (metaInput *MetaInput) Target() string {
	if metaInput.ReqResp != nil && metaInput.ReqResp.URL.URL != nil {
		return metaInput.ReqResp.URL.String()
	}
	return metaInput.Input
}

// URL returns request url
func (metaInput *MetaInput) URL() (*urlutil.URL, error) {
	instance, err := urlutil.ParseAbsoluteURL(metaInput.Target(), false)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// Port returns the port of the target
// if port is not present then empty string is returned
func (metaInput *MetaInput) Port() string {
	target, err := urlutil.ParseAbsoluteURL(metaInput.Input, false)
	if err != nil {
		return ""
	}
	return target.Port()
}

// Address return the remote address of target
// Note: it does not resolve the domain to ip
// it is meant to be used by hosterrorsCache if invalid metainput
// is provided then it uses a random ksuid as hostname to avoid skipping valid targets
func (metaInput *MetaInput) Address() string {
	var hostname, port string
	target, err := urlutil.ParseAbsoluteURL(metaInput.Target(), false)
	if err != nil {
		if metaInput.CustomIP == "" {
			// since this is used in hosterrorscache we add a random id
			// which will never be used to avoid skipping valid targets
			hostname = fmt.Sprintf("invalid-%s", ksuid.New().String())
		}
	} else {
		hostname = target.Hostname()
		port = target.Port()
		if port == "" {
			switch target.Scheme {
			case urlutil.HTTP:
				port = "80"
			case urlutil.HTTPS:
				port = "443"
			default:
				port = "80"
			}
		}
	}
	if metaInput.CustomIP != "" {
		hostname = metaInput.CustomIP
	}
	if port == "" {
		if strings.HasPrefix(hostname, "http://") {
			port = "80"
		} else if strings.HasPrefix(hostname, "https://") {
			port = "443"
		}
	}
	return net.JoinHostPort(hostname, port)
}

// ID returns a unique id/hash for metainput
func (metaInput *MetaInput) ID() string {
	if metaInput.CustomIP != "" {
		return fmt.Sprintf("%s-%s", metaInput.Input, metaInput.CustomIP)
	}
	if metaInput.ReqResp != nil {
		return metaInput.ReqResp.ID()
	}
	return metaInput.Input
}

func (metaInput *MetaInput) MarshalString() (string, error) {
	b, err := metaInput.marshalToBuffer()
	return b.String(), err
}

func (metaInput *MetaInput) MustMarshalString() string {
	marshaled, _ := metaInput.MarshalString()
	return marshaled
}

func (metaInput *MetaInput) MarshalBytes() ([]byte, error) {
	b, err := metaInput.marshalToBuffer()
	return b.Bytes(), err
}

func (metaInput *MetaInput) MustMarshalBytes() []byte {
	marshaled, _ := metaInput.MarshalBytes()
	return marshaled
}

func (metaInput *MetaInput) Unmarshal(data string) error {
	return jsoniter.NewDecoder(strings.NewReader(data)).Decode(metaInput)
}

func (metaInput *MetaInput) Clone() *MetaInput {
	metaInput.mu.Lock()
	defer metaInput.mu.Unlock()

	input := NewMetaInput()
	input.Input = metaInput.Input
	input.CustomIP = metaInput.CustomIP
	input.hash = metaInput.hash
	if metaInput.ReqResp != nil {
		input.ReqResp = metaInput.ReqResp.Clone()
	}
	return input
}

func (metaInput *MetaInput) PrettyPrint() string {
	if metaInput.CustomIP != "" {
		return fmt.Sprintf("%s [%s]", metaInput.Input, metaInput.CustomIP)
	}
	if metaInput.ReqResp != nil {
		return fmt.Sprintf("%s [%s]", metaInput.ReqResp.URL.String(), metaInput.ReqResp.Request.Method)
	}
	return metaInput.Input
}

// GetScanHash returns a unique hash that represents a scan by hashing (metainput + templateId)
func (metaInput *MetaInput) GetScanHash(templateId string) string {
	// there may be some cases where metainput is changed ex: while executing self-contained template etc
	// but that totally changes the scanID/hash so to avoid that we compute hash only once
	// and reuse it for all subsequent calls
	metaInput.mu.Lock()
	defer metaInput.mu.Unlock()

	if metaInput.hash == "" {
		var rawRequest string
		if metaInput.ReqResp != nil {
			rawRequest = metaInput.ReqResp.ID()
		}
		metaInput.hash = getMd5Hash(templateId + ":" + metaInput.Input + ":" + metaInput.CustomIP + rawRequest)
	}
	return metaInput.hash
}

func getMd5Hash(data string) string {
	bin := md5.Sum([]byte(data))
	return string(bin[:])
}
