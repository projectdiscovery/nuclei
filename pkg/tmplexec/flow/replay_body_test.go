package flow

import (
	"fmt"
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

func TestReplayBodyMatchesLargeProbe(t *testing.T) {
	runtime := goja.New()
	if err := registerReplayBody(runtime); err != nil {
		t.Fatal(err)
	}
	_, err := runtime.RunString(`
		function repeatStr(s, n) {
			var r = '';
			while (n > 0) {
				if (n & 1) r += s;
				s += s;
				n >>= 1;
			}
			return r;
		}
		function originalProbe(sizeMib, parts) {
			var size = sizeMib * 1048576;
			var nested = repeatStr('[a]', 62);
			var part = '--\nContent-Disposition:name=a[]' + nested + ';filename=\n\n';
			var base = repeatStr(part, parts);
			var fillerCount = Math.floor((size - base.length) / 3);
			var filler = repeatStr('x:\n', fillerCount);
			var body = '--\n' + filler + base.substring(3);
			return body.substring(0, body.length - 1);
		}
		function replayProbe(sizeMib, parts) {
			var size = sizeMib * 1048576;
			var nested = repeatStr('[a]', 62);
			var part = '--\nContent-Disposition:name=a[]' + nested + ';filename=\n\n';
			var fillerCount = Math.floor((size - part.length * parts) / 3);
			return replayBody([['--\n', 1], ['x:\n', fillerCount], [part.substring(3), 1], [part, parts - 1]], 1);
		}
	`)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := goja.AssertFunction(runtime.Get("originalProbe"))
	replay, _ := goja.AssertFunction(runtime.Get("replayProbe"))
	for _, test := range []struct {
		sizeMib int
		parts   int
	}{{1, 4000}, {8, 1020}, {20, 1020}} {
		t.Run(fmt.Sprintf("%dMiB", test.sizeMib), func(t *testing.T) {
			args := []goja.Value{runtime.ToValue(test.sizeMib), runtime.ToValue(test.parts)}
			originalValue, err := original(goja.Undefined(), args...)
			if err != nil {
				t.Fatal(err)
			}
			replayValue, err := replay(goja.Undefined(), args...)
			if err != nil {
				t.Fatal(err)
			}
			body := replayValue.Export().(*httpbody.ReplayBody)
			reader := body.NewReader()
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != originalValue.String() {
				t.Fatalf("%d MiB probe differs from original", test.sizeMib)
			}
		})
	}
}
