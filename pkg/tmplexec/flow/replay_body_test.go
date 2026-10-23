package flow

import (
	"io"
	"testing"

	"github.com/projectdiscovery/goja"
	httpbody "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

func TestReplayBodyBuiltin(t *testing.T) {
	runtime := goja.New()
	if err := registerReplayBody(runtime); err != nil {
		t.Fatal(err)
	}
	value, err := runtime.RunString(`replayBody([['abc', 3], ['xyz', 1]], 1)`)
	if err != nil {
		t.Fatal(err)
	}
	body, ok := value.Export().(*httpbody.ReplayBody)
	if !ok {
		t.Fatalf("unexpected replay body type %T", value.Export())
	}
	reader := body.NewReader()
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "abcabcabcxy" {
		t.Fatalf("replay body = %q, err = %v", got, err)
	}
}
