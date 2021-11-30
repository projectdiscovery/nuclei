package projectfile

import (
	"fmt"
	"net/http"

	"github.com/projectdiscovery/hmap/store/hybrid"
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

func (pf *ProjectFile) Get(req []byte) (*http.Response, error) {
	reqHash, err := hash(req)
	if err != nil {
		return nil, err
	}

	data, ok := pf.hm.Get(reqHash)
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	var httpRecord HTTPRecord
	httpRecord.Response = newInternalResponse()
	if err := unmarshal(data, &httpRecord); err != nil {
		return nil, err
	}

	return fromInternalResponse(httpRecord.Response), nil
}

func (pf *ProjectFile) Set(req []byte, resp *http.Response, data []byte) error {
	reqHash, err := hash(req)
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
