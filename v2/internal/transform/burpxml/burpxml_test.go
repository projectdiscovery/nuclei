package burpxml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBurpXML(t *testing.T) {
	data, err := ioutil.ReadFile("burp.xml")
	require.Nil(t, err, "could not read burp xml")

	items := &items{}
	err = xml.NewDecoder(strings.NewReader(string(data))).Decode(items)
	require.Nil(t, err, "could not parse burp xml")

	for _, item := range items.Item {
		if item.Request.Base64 != "" {
			fmt.Printf("%v\n", item.Request.Base64)
			decoded, err := base64.StdEncoding.DecodeString(item.Request.Text)
			require.Nil(t, err, "could not parse burp xml")

			item.Request.Base64 = ""
			item.Request.Text = string(decoded)
		}
		fmt.Printf("%+v\n", item)
	}
}
