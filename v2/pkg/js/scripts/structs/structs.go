package structs

import (
	"github.com/dop251/goja"
	"github.com/projectdiscovery/gostruct"
)

// Module is the goja module for structs.
type Module struct{}

// Enable enables the structs module for the goja runtime.
func (m *Module) Enable(runtime *goja.Runtime) {
	// TODO: Expose in browser
}

// StructsUnpack the byte slice (presumably packed by Pack(format, msg)) according to the given format.
// The result is a []interface{} slice even if it contains exactly one item.
// The byte slice must contain not less the amount of data required by the format
// (len(msg) must more or equal CalcSize(format)).
func StructsUnpack(format string, msg []byte) ([]interface{}, error) {
	return gostruct.UnPack(buildFormatSliceFromStringFormat(format), msg)
}

// StructsPack returns a byte slice containing the values of msg slice packed according to the given format.
// The items of msg slice must match the values required by the format exactly.
func StructsPack(format string, msg []interface{}) ([]byte, error) {
	return gostruct.Pack(buildFormatSliceFromStringFormat(format), msg)
}

// StructsCalcSize returns the number of bytes needed to pack the values according to the given format.
func StructsCalcSize(format string) (int, error) {
	return gostruct.CalcSize(buildFormatSliceFromStringFormat(format))
}

func buildFormatSliceFromStringFormat(format string) []string {
	var formats []string
	temp := ""

	for _, c := range format {
		if c >= '0' && c <= '9' {
			temp += string(c)
		} else {
			if temp != "" {
				formats = append(formats, temp+string(c))
				temp = ""
			} else {
				formats = append(formats, string(c))
			}
		}
	}
	if temp != "" {
		formats = append(formats, temp)
	}
	return formats
}
