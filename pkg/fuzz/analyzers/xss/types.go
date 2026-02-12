package xss

import "strings"

const (
	AnalyzerName   = "xss_context"
	DefaultCanary  = "nuclei9x7q<>\"'`"
	maxReflections = 10
)

type ContextType int

const (
	ContextUnknown               ContextType = iota
	ContextHTMLText                          // <div>MARKER</div>
	ContextAttributeDoubleQuoted             // <input value="MARKER">
	ContextAttributeSingleQuoted             // <input value='MARKER'>
	ContextAttributeUnquoted                 // <input value=MARKER>
	ContextScriptBlock                       // <script>MARKER</script>
	ContextScriptStringDouble                // <script>var x="MARKER"</script>
	ContextScriptStringSingle                // <script>var x='MARKER'</script>
	ContextScriptTemplate                    // <script>var x=`MARKER`</script>
	ContextComment                           // <!-- MARKER -->
	ContextRCDATA                            // <textarea>MARKER</textarea>
	ContextStyle                             // <style>MARKER</style>
	ContextURLAttribute                      // <a href="MARKER">
)

func (c ContextType) String() string {
	switch c {
	case ContextHTMLText:
		return "html_text"
	case ContextAttributeDoubleQuoted:
		return "attr_double_quoted"
	case ContextAttributeSingleQuoted:
		return "attr_single_quoted"
	case ContextAttributeUnquoted:
		return "attr_unquoted"
	case ContextScriptBlock:
		return "script_block"
	case ContextScriptStringDouble:
		return "script_string_double"
	case ContextScriptStringSingle:
		return "script_string_single"
	case ContextScriptTemplate:
		return "script_template"
	case ContextComment:
		return "comment"
	case ContextRCDATA:
		return "rcdata"
	case ContextStyle:
		return "style"
	case ContextURLAttribute:
		return "url_attribute"
	default:
		return "unknown"
	}
}

type CharacterSet struct {
	LessThan    bool // <
	GreaterThan bool // >
	SingleQuote bool // '
	DoubleQuote bool // "
	Slash       bool // /
	Backtick    bool // `
}

type ReflectionInfo struct {
	Context        ContextType
	AvailableChars CharacterSet
	AttributeName  string
	PriorityWeight int // lower = higher priority (tried first)
}

func isURLAttribute(name string) bool {
	switch strings.ToLower(name) {
	case "href", "src", "action", "formaction", "poster", "data",
		"codebase", "cite", "background", "dynsrc", "lowsrc":
		return true
	default:
		return false
	}
}

func DetectAvailableChars(reflected, original string) CharacterSet {
	return CharacterSet{
		LessThan:    !strings.Contains(original, "<") || strings.Contains(reflected, "<"),
		GreaterThan: !strings.Contains(original, ">") || strings.Contains(reflected, ">"),
		SingleQuote: !strings.Contains(original, "'") || strings.Contains(reflected, "'"),
		DoubleQuote: !strings.Contains(original, "\"") || strings.Contains(reflected, "\""),
		Slash:       !strings.Contains(original, "/") || strings.Contains(reflected, "/"),
		Backtick:    !strings.Contains(original, "`") || strings.Contains(reflected, "`"),
	}
}
