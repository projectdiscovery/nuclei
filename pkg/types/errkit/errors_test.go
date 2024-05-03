package errkit

import (
	"testing"

	"github.com/pkg/errors"
	"go.uber.org/multierr"

	stderrors "errors"
)

// what are these tests ?
// Below tests check for interoperability of this package with other error packages
// like pkg/errors and go.uber.org/multierr and std errors as well

func TestErrorAs(t *testing.T) {
	// Create a new error with a specific class and wrap it
	x := New("this is a nuclei error").SetClass(ErrClassNetworkPermanent).Build()
	y := errors.Wrap(x, "this is a wrap error")

	// Attempt to unwrap the error to a specific type
	ne := &ErrorX{}
	if !errors.As(y, &ne) {
		t.Fatal("expected to be able to unwrap")
	}

	// Wrap the specific error type into another error and try unwrapping again
	wrapped := Wrap(ne, "this is a wrapped error")
	if !errors.As(wrapped, &ne) {
		t.Fatal("expected to be able to unwrap")
	}

	// Combine multiple errors into a multierror and attempt to unwrap to the specific type
	errs := []error{
		stderrors.New("this is a std error"),
		x,
		errors.New("this is a pkg error"),
	}
	multi := multierr.Combine(errs...)
	if !errors.As(multi, &ne) {
		t.Fatal("expected to be able to unwrap")
	}
}

func TestErrorIs(t *testing.T) {
	// Create a new error, wrap it, and check if the original error can be found
	x := New("this is a nuclei error").SetClass(ErrClassNetworkPermanent).Build()
	y := errors.Wrap(x, "this is a wrap error")
	if !errors.Is(y, x) {
		t.Fatal("expected to be able to find the original error")
	}

	// Wrap the original error with a custom wrapper and check again
	wrapped := Wrap(x, "this is a wrapped error")
	if !stderrors.Is(wrapped, x) {
		t.Fatal("expected to be able to find the original error")
	}

	// Combine multiple errors into a multierror and check if the original error can be found
	errs := []error{
		stderrors.New("this is a std error"),
		x,
		errors.New("this is a pkg error"),
	}
	multi := multierr.Combine(errs...)
	if !errors.Is(multi, x) {
		t.Fatal("expected to be able to find the original error")
	}
}
