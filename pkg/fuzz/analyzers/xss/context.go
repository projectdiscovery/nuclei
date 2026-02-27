package xss

// XSSContext represents the precise injection context of a reflected value.
type XSSContext int

const (
	ContextHTMLText              XSSContext = iota // <div>REFLECTED</div>
	ContextHTMLComment                             // <!-- REFLECTED -->
	ContextAttrValueDoubleQuoted                   // <input value="REFLECTED">
	ContextAttrValueSingleQuoted                   // <input value='REFLECTED'>
	ContextAttrValueUnquoted                       // <input value=REFLECTED>
	ContextEventHandler                            // <div onclick="REFLECTED">
	ContextURLAttribute                            // <a href="REFLECTED">
	ContextScriptStringDouble                      // <script>var x = "REFLECTED"</script>
	ContextScriptStringSingle                      // <script>var x = 'REFLECTED'</script>
	ContextScriptTemplateLiteral                   // <script>`REFLECTED`</script>
	ContextScriptExpression                        // <script>var x = REFLECTED</script>
	ContextScriptComment                           // <script>// REFLECTED</script>
	ContextScriptBlockComment                      // <script>/* REFLECTED */</script>
	ContextCSSValue                                // <style>.x { color: REFLECTED }</style>
	ContextCSSURL                                  // <style>url(REFLECTED)</style>
	ContextStyleAttribute                          // style="color: REFLECTED"
	ContextUnknown
)

var contextStrings = map[XSSContext]string{
	ContextHTMLText:              "xss_context:html_text",
	ContextHTMLComment:           "xss_context:html_comment",
	ContextAttrValueDoubleQuoted: "xss_context:attr_value_double_quoted",
	ContextAttrValueSingleQuoted: "xss_context:attr_value_single_quoted",
	ContextAttrValueUnquoted:     "xss_context:attr_value_unquoted",
	ContextEventHandler:          "xss_context:event_handler",
	ContextURLAttribute:          "xss_context:url_attribute",
	ContextScriptStringDouble:    "xss_context:script_string_double",
	ContextScriptStringSingle:    "xss_context:script_string_single",
	ContextScriptTemplateLiteral: "xss_context:script_template_literal",
	ContextScriptExpression:      "xss_context:script_expression",
	ContextScriptComment:         "xss_context:script_comment",
	ContextScriptBlockComment:    "xss_context:script_block_comment",
	ContextCSSValue:              "xss_context:css_value",
	ContextCSSURL:                "xss_context:css_url",
	ContextStyleAttribute:        "xss_context:style_attribute",
	ContextUnknown:               "xss_context:unknown",
}

// String returns the normalized identifier for this XSS context.
func (c XSSContext) String() string {
	if s, ok := contextStrings[c]; ok {
		return s
	}
	return "xss_context:unknown"
}
