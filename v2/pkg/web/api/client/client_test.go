package client

import "testing"

func TestClient(t *testing.T) {
	New(WithBaseURL("https://api.nuclei.com"), WithBasicAuth("iceman", "password"))
}
