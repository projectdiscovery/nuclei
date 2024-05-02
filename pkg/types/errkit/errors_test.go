package errkit

import (
	"testing"

	"github.com/pkg/errors"
)

func TestErrorAs(t *testing.T) {
	x := New("this is a nuclei error").SetClass(ErrClassNetworkPermanent).Build()

	// using wrap to create a new error
	y := errors.Wrap(x, "this is a wrap error")

	ne := &ErrorX{}
	if !errors.As(y, &ne) {
		t.Fatal("expected to be able to unwrap")
	}

	// use ErrorX to wrap
}

func TestErrorIs(t *testing.T) {

}
