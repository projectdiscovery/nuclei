package file

import (
	"errors"
	"io"
	"log"
)

func isFatalErr(err error) bool {
	log.Println(err)
	return err != nil && !errors.Is(err, io.EOF)
}
