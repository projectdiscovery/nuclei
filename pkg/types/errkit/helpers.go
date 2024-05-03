package errkit

// Combine combines multiple errors into a single error
func Combine(errs ...error) error {
	if len(errs) == 0 {
		return nil
	}
	x := &ErrorX{}
	for _, err := range errs {
		if err == nil {
			continue
		}
		parseError(x, err)
	}
	return x
}

// Wrap wraps the given error with the message
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	x.Msgf(message)
	return x
}

// Wrapf wraps the given error with the message
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	x.Msgf(format, args...)
	return x
}

// Errors returns all underlying errors there were appended or joined
func Errors(err error) []error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	return x.errs
}

// Append appends given errors and returns a new error
// it ignores all nil errors
func Append(errs ...error) error {
	if len(errs) == 0 {
		return nil
	}
	x := &ErrorX{}
	for _, err := range errs {
		if err == nil {
			continue
		}
		parseError(x, err)
	}
	return x
}

// Cause returns the original error that caused this error
func Cause(err error) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	return x.Cause()
}

// WithMessage
func WithMessage(err error, message string) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	x.Msgf(message)
	return x
}

// WithMessagef
func WithMessagef(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	x := &ErrorX{}
	parseError(x, err)
	x.Msgf(format, args...)
	return x
}
