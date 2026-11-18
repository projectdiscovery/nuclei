package gojs_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"testing"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

type counter struct{ n int }

func (c *counter) Inc() int {
	c.n++

	return c.n
}

func TestGetClassConstructorReturnsNewObjects(t *testing.T) {
	t.Parallel()

	prototype := new(counter)
	runtime := goja.New()

	err := runtime.Set("Counter", gojs.GetClassConstructor(prototype))
	if err != nil {
		t.Fatal(err)
	}

	value, err := runtime.RunString(`
		const first = new Counter();
		first.Inc();
		new Counter().Inc();
	`)
	if err != nil {
		t.Fatal(err)
	}

	if got := value.ToInteger(); got != 1 {
		t.Errorf("new Counter().Inc() = %d, want 1", got)
	}

	if prototype.n != 0 {
		t.Errorf("prototype.n = %d, want 0", prototype.n)
	}
}
