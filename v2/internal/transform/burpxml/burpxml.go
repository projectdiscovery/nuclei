package burpxml

import (
	"encoding/base64"
	"encoding/xml"
	"os"

	"github.com/projectdiscovery/nuclei/v2/internal/transform/raw"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/fuzzing"
)

type items struct {
	Item []struct {
		URL     string `xml:"url"`
		Request struct {
			Text   string `xml:",chardata"`
			Base64 string `xml:"base64,attr"`
		} `xml:"request"`
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

	for _, item := range items.Item {
		if item.Request.Base64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(item.Request.Text)
			if err != nil {
				continue
			}
			item.Request.Base64 = ""
			item.Request.Text = string(decoded)
		}
		parsed, err := raw.Parse(item.Request.Text, item.URL)
		if err != nil {
			continue
		}
		callback(parsed)
	}
	return nil
}
