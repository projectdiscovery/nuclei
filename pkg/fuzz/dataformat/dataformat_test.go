package dataformat

import (
	"testing"
)

func TestDataformatDecodeEncode_JSON(t *testing.T) {
	obj := `{"foo":"bar"}`

	decoded, err := Decode(obj)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DataFormat != "json" {
		t.Fatal("unexpected data format")
	}
	if decoded.Data["foo"] != "bar" {
		t.Fatal("unexpected data")
	}

	encoded, err := Encode(decoded.Data, decoded.DataFormat)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != obj {
		t.Fatal("unexpected data")
	}
}

func TestDataformatDecodeEncode_XML(t *testing.T) {
	obj := `<foo attr="baz">bar</foo>`

	decoded, err := Decode(obj)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DataFormat != "xml" {
		t.Fatal("unexpected data format")
	}
	if decoded.Data["foo"].(map[string]interface{})["#text"] != "bar" {
		t.Fatal("unexpected data")
	}
	if decoded.Data["foo"].(map[string]interface{})["-attr"] != "baz" {
		t.Fatal("unexpected data")
	}

	encoded, err := Encode(decoded.Data, decoded.DataFormat)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != obj {
		t.Fatal("unexpected data")
	}
}
