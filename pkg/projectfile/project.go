package projectfile

import (
	"net/http"
	"regexp"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/hmap/store/hybrid"
)

var (
	ErrNotFound          = errors.New("not found")
	regexUserAgent       = regexp.MustCompile(`(?mi)\r\nUser-Agent: .+\r\n`)
	regexDefaultInteract = regexp.MustCompile(`(?mi)[a-zA-Z1-9%.]+interact.sh`)
)

type Options struct {
	Path    string
	Cleanup bool
}

type ProjectFile struct {
	Path string
	hm   *hybrid.HybridMap
}

func New(options *Options) (*ProjectFile, error) {
	var p ProjectFile
	hOptions := hybrid.DefaultDiskOptions
	hOptions.Path = options.Path
	hOptions.Cleanup = options.Cleanup
	var err error
	p.hm, err = hybrid.New(hOptions)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func (pf *ProjectFile) cleanupData(data []byte) []byte {
	// ignore all user agents
	data = regexUserAgent.ReplaceAll(data, []byte("\r\n"))
	// ignore interact markers
	return regexDefaultInteract.ReplaceAll(data, []byte(""))
}

func (pf *ProjectFile) Get(req []byte) (*http.Response, error) {
	reqHash, err := hash(pf.cleanupData(req))
	if err != nil {
		return nil, err
	}

	data, ok := pf.hm.Get(reqHash)
	if !ok {
		return nil, ErrNotFound
	}

	var httpRecord HTTPRecord
	httpRecord.Response = newInternalResponse()
	if err := unmarshal(data, &httpRecord); err != nil {
		return nil, err
	}

	return fromInternalResponse(httpRecord.Response), nil
}

func (pf *ProjectFile) Set(req []byte, resp *http.Response, data []byte) error {
	reqHash, err := hash(pf.cleanupData(req))
	if err != nil {
		return err
	}

	var httpRecord HTTPRecord
	httpRecord.Request = req
	httpRecord.Response = toInternalResponse(resp, data)
	data, err = marshal(httpRecord)
	if err != nil {
		return err
	}

	return pf.hm.Set(reqHash, data)
}

func (pf *ProjectFile) Close() {
	pf.hm.Close()
}
