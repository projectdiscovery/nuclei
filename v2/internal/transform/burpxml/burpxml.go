package burpxml

import (
	"encoding/xml"
	"os"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/fuzzing"
)

type items struct {
	Item []struct {
		URL  string `xml:"url"`
		Host struct {
			Text string `xml:",chardata"`
		} `xml:"host"`
		Port     string `xml:"port"`
		Protocol string `xml:"protocol"`
		Method   string `xml:"method"`
		Path     string `xml:"path"`
		Request  struct {
			Text   string `xml:",chardata"`
			Base64 string `xml:"base64,attr"`
		} `xml:"request"`
		Mimetype string `xml:"mimetype"`
	} `xml:"item"`
}

// Parse parses a curl command and returns the normalized request.
func Parse(path string, callback func(*fuzzing.NormalizedRequest)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	items := &items{}
	err = xml.NewDecoder(file).Decode(items)
	if err != nil {
		return err
	}
	//
	//	for _, item := range items.Item {
	//		req, err := http.NewRequest(item.Method, item.URL, nil)
	//		if err != nil {
	//			// log
	//			continue
	//		}
	//		for k, v := range data.headers {
	//			req.Header.Set(k, v)
	//		}
	//		if data.data != "" {
	//			req.ContentLength = int64(len(data.data))
	//			req.Body = ioutil.NopCloser(strings.NewReader(data.data))
	//		}
	//
	//		retryable, err := retryablehttp.FromRequest(req)
	//		if err != nil {
	//			return nil, errors.Wrap(err, "could not create retryable request")
	//		}
	//
	//		normalized, err := fuzzing.NormalizeRequest(retryable)
	//		if err != nil {
	//			return nil, errors.Wrap(err, "could not create normalized request")
	//		}
	//	}
	//
	//	return normalized, nil
	//}
	return nil
}
