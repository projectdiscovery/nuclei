package dataformat

import "testing"

func TestFormDecodeEncode_DuplicateParameters(t *testing.T) {
	form := NewForm()
	decoded, err := form.Decode("foo=a&foo=b&foo=c")
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := form.Encode(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != "foo=a&foo=b&foo=c" {
		t.Fatalf("unexpected form encoding: %q", encoded)
	}
}

func TestFormDecodeEncode_DoesNotMergePrefixParameterNames(t *testing.T) {
	form := NewForm()
	decoded, err := form.Decode("foo=a&foobar=b&foobar=c")
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := form.Encode(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != "foo=a&foobar=b&foobar=c" {
		t.Fatalf("unexpected form encoding: %q", encoded)
	}
}
