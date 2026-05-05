package vardump

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/yassinebenaid/godump"
)

// variables is a map of variables
type variables = map[string]any

// DumpVariables dumps the variables in a pretty format
func DumpVariables(data variables) string {
	d := godump.Dumper{
		Indentation:             "  ",
		HidePrivateFields:       false,
		ShowPrimitiveNamedTypes: true,
	}

	d.Theme = godump.Theme{
		String:        godump.RGB{R: 138, G: 201, B: 38},
		Quotes:        godump.RGB{R: 112, G: 214, B: 255},
		Bool:          godump.RGB{R: 249, G: 87, B: 56},
		Number:        godump.RGB{R: 10, G: 178, B: 242},
		Types:         godump.RGB{R: 0, G: 150, B: 199},
		Address:       godump.RGB{R: 205, G: 93, B: 0},
		PointerTag:    godump.RGB{R: 110, G: 110, B: 110},
		Nil:           godump.RGB{R: 219, G: 57, B: 26},
		Func:          godump.RGB{R: 160, G: 90, B: 220},
		Fields:        godump.RGB{R: 189, G: 176, B: 194},
		Chan:          godump.RGB{R: 195, G: 154, B: 76},
		UnsafePointer: godump.RGB{R: 89, G: 193, B: 180},
		Braces:        godump.RGB{R: 185, G: 86, B: 86},
	}

	return d.Sprint(process(data, Limit))
}

// process is a helper function that processes the variables
// and returns a new map of variables
func process(data variables, limit int) variables {
	keys := mapsutil.GetSortedKeys(data)
	vars := make(variables)

	if limit == 0 {
		limit = 255
	}

	for _, k := range keys {
		v := types.ToString(data[k])
		v = strings.ReplaceAll(strings.ReplaceAll(v, "\r", " "), "\n", " ")
		if len(v) > limit {
			v = v[:limit]
			v += " [...]"
		}

		vars[k] = v
	}

	return vars
}
