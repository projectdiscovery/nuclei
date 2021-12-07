package yaml

import (
	"io"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var validate *validator.Validate

// DecodeAndValidate is a wrapper for yaml Decode adding struct validation
func DecodeAndValidate(r io.Reader, v interface{}) error {
	if err := yaml.NewDecoder(r).Decode(v); err != nil {
		return err
	}
	if validate == nil {
		validate = validator.New()
	}

	if err := validate.Struct(v); err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return err
		}
		errs := []string{}
		for _, err := range err.(validator.ValidationErrors) {
			errs = append(errs, err.Namespace()+": "+err.Tag())
		}
		return errors.Wrap(errors.New(strings.Join(errs, ", ")), "validation failed for these fields")
	}
	return nil
}
