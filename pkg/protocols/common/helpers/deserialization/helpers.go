package deserialization

import (
	"github.com/valyala/bytebufferpool"
)

func InsertInto(s string, interval int, sep rune) string {
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteString(string(char))
		if i%interval == before && i != last {
			buffer.WriteString(string(sep))
		}
	}
	buffer.WriteString(string(sep))
	return buffer.String()
}
