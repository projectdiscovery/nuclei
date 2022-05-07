package errors

import (
	"io"
	"log"

	"github.com/pkg/errors"
)

// IsFileErrFatal determines if the error detected during I/O is fatal
func IsFileErrFatal(err error) bool {
	log.Println(err)
	return err != nil && !errors.Is(err, io.EOF)
}
