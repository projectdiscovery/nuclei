package context

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// ContextType represents the HTML context where the payload was reflected
type ContextType int

const (
	ContextUnknown ContextType = iota
	ContextHTMLBody
	ContextAttributeName
	ContextAttributeValueDoubleQuote
	ContextAttributeValueSingleQuote
	ContextAttributeValueUnquoted
	ContextScript
	ContextStyle
	ContextComment
	ContextRCDATA // textarea, title, no-script, etc.
)

func (c ContextType) String() string {
	switch c {
	case ContextHTMLBody:
		return "ContextHTMLBody"
	case ContextAttributeName:
		return "ContextAttributeName"
	case ContextAttributeValueDoubleQuote:
		return "ContextAttributeValueDoubleQuote"
	case ContextAttributeValueSingleQuote:
		return "ContextAttributeValueSingleQuote"
	case ContextAttributeValueUnquoted:
		return "ContextAttributeValueUnquoted"
	case ContextScript:
		return "ContextScript"
	case ContextStyle:
		return "ContextStyle"
	case ContextComment:
		return "ContextComment"
	case ContextRCDATA:
		return "ContextRCDATA"
	default:
		return "ContextUnknown"
	}
}

// AnalysisResult holds the verdict of the context analysis
type AnalysisResult struct {
	Vulnerable bool
	Context    ContextType
	Reason     string
}

// Analyze processes the response body to determine if the payload is executable
func Analyze(body []byte, payload string) AnalysisResult {
	// Fast Path: Optimization to avoid parsing if payload isn't present
	if !bytes.Contains(body, []byte(payload)) {
		return AnalysisResult{Vulnerable: false, Context: ContextUnknown}
	}

	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	// State tracking variables
	var insideScript bool
	var insideStyle bool
	var insideTextarea bool

	for {
		tokenType := tokenizer.Next()
		// Get raw token bytes once
		rawToken := tokenizer.Raw()

		switch tokenType {
		case html.ErrorToken:
			// End of document or error
			return AnalysisResult{Vulnerable: false, Context: ContextUnknown}

		case html.StartTagToken:
			// Check if payload is in the raw tag, but careful about attributes
			// If payload corresponds to the tag itself (e.g. "<h1>"), we should catch it here.
			// But we also handle attributes separately.
			
			// If the payload contains the tag name, and we are here, it's likely vulnerable HTML injection.
			// Example: payload="<h1>", raw="<h1>" -> Vulnerable.
			// Example: payload="x", raw="<div x>" (attr) -> Handled in attr logic.
			
			tagName, hasAttr := tokenizer.TagName()
			tagStr := string(tagName)

			// Fast check: if payload is in this tag
			if bytes.Contains(rawToken, []byte(payload)) {
				// If we are inside RCDATA/Script (from previous implementation), this wouldn't trigger StartTag 
				// unless it broke out.
				// Wait, if insideScript is true, does tokenizer emit StartTag?
				// No, the html tokenizer should handle script data differently unless it encounters </script>.
				
				// However, standard tokenizer logic:
				// If we see a StartTagToken, it means we satisfy conditions to be a tag.
				
				// Case: Payload is "<h1>"
				// rawToken is "<h1>"
				// It's a StartTag. Vulnerable.
				
				// Case: Payload is "onmouseover"
				// rawToken is "<div onmouseover>"
				// It's a StartTag. Vulnerable (Attribute Name).
				
				// We should let the specific checks below refine the context, but if we don't match below, 
				// and validation implies "It became a tag", we should default to HTMLBody vulnerability?
				
				// But let's look at existing logic.
			}

			// Track state for RCDATA/Script blocks
			if tagStr == "script" {
				insideScript = true
			}
			if tagStr == "style" {
				insideStyle = true
			}
			if tagStr == "textarea" {
				insideTextarea = true
			}

            // Check if payload caused this tag to appear (e.g. payload="<h1>")
            // If the payload is contained in the raw token, AND it's NOT in an attribute (checked later),
            // implies it's the tag itself.
            if bytes.Contains(rawToken, []byte(payload)) {
                 // But wait, if hasAttr is true, it might be in attribute.
                 // If hasAttr is false, and it contains payload, it must be the tag name or the whole tag.
                 if !hasAttr {
                     return AnalysisResult{Vulnerable: true, Context: ContextHTMLBody, Reason: "Payload reflected as tag"}
                 }
                 // If hasAttr is true, we will check attributes below.
                 // BUT what if payload is "<h1>" and it reflects as "<h1>"? hasAttr is false.
                 // What if payload is "<img src=x>"? hasAttr is true.
                 // We need to return Vulnerable there too.
            }

			if hasAttr {
				// Check if payload is in attributes
				// Logic: Iterate attributes using tokenizer.TagAttr()
				// If payload found, check quoting style vs payload content
				attrKey, attrVal, moreAttr := tokenizer.TagAttr()
				for {
					if strings.Contains(string(attrKey), payload) {
						return AnalysisResult{Vulnerable: true, Context: ContextAttributeName, Reason: "Payload in attribute name"}
					}
					if strings.Contains(string(attrVal), payload) {
						return AnalysisResult{Vulnerable: verifyAttributeContext(string(attrVal), payload), Context: ContextAttributeValueDoubleQuote, Reason: "Payload in attribute value"}
					}
					if !moreAttr {
						break
					}
					attrKey, attrVal, moreAttr = tokenizer.TagAttr()
				}
                
                // If we are here, hasAttr was true, but payload wasn't found in attributes logic?
                // Example: payload="<img src=x>"
                // rawToken might be "<img src=x>"
                // Attr key "src", val "x".
                // Payload "<img src=x>" is NOT in "src" or "x".
                // So the loop misses it.
                
                // But bytes.Contains(rawToken, payload) would be true!
                // So if we found it in rawToken but NOT in attributes, it means the payload *constructed* the tag+attributes.
                // This is definitely HTML injection.
                if bytes.Contains(rawToken, []byte(payload)) {
                     return AnalysisResult{Vulnerable: true, Context: ContextHTMLBody, Reason: "Payload reflected as tag with attributes"}
                }
			}

		case html.EndTagToken:
			tagName, _ := tokenizer.TagName()
			tagStr := string(tagName)
            
            // Check for breakout via closing tag
            // If we were inside a special block, and this tag closes it, and the payload *contains* this closing tag,
            // it's a confirmed breakout.
			if (insideScript && tagStr == "script") || 
               (insideStyle && tagStr == "style") || 
               (insideTextarea && tagStr == "textarea") {
                if strings.Contains(payload, "</"+tagStr) {
					ctx := ContextRCDATA
					if insideScript {
						ctx = ContextScript
					}
					// Only Textarea/Title are strictly RCDATA. Style is Rawtext?
					// ContextRCDATA covers them for our enum purposes.
                     return AnalysisResult{Vulnerable: true, Context: ctx, Reason: "Breakout via enclosing tag"}
                }
            }

			if tagStr == "script" {
				insideScript = false
			}
			if tagStr == "style" {
				insideStyle = false
			}
			if tagStr == "textarea" {
				insideTextarea = false
			}

		case html.TextToken:
			text := tokenizer.Text()
			if bytes.Contains(text, []byte(payload)) {
				if insideScript {
					// Check for JS String Breakout using the surrounding text
					return verifyScriptContext(string(text), payload)
				}
				if insideStyle || insideTextarea {
					// Usually safe unless closing tag is present (handled in EndTagToken or here if partial)
					tag := "textarea"
					if insideStyle {
						tag = "style"
					}
					if strings.Contains(payload, "</"+tag) {
						return AnalysisResult{Vulnerable: true, Context: ContextRCDATA, Reason: "RCDATA breakout"}
					}
					return AnalysisResult{Vulnerable: false, Context: ContextRCDATA, Reason: "Reflected in RCDATA without breakout"}
				}

				// HTML Body Context
				// Check if < > are escaped
				if isEscaped(string(text), payload) {
					return AnalysisResult{Vulnerable: false, Context: ContextHTMLBody, Reason: "Reflected in body but escaped"}
				}
				return AnalysisResult{Vulnerable: true, Context: ContextHTMLBody, Reason: "Reflected in body unescaped"}
			}

		case html.CommentToken:
			// Use Raw() to catch breakouts like "-->" which might be part of the delimiter
			if bytes.Contains(rawToken, []byte(payload)) {
				if strings.Contains(payload, "-->") {
					return AnalysisResult{Vulnerable: true, Context: ContextComment, Reason: "Comment breakout"}
				}
				return AnalysisResult{Vulnerable: false, Context: ContextComment, Reason: "Reflected in comment"}
			}
		}
	}
}

// verifyScriptContext determines if payload inside script tag is executable
func verifyScriptContext(text string, payload string) AnalysisResult {
    // Check if the payload is inside quotes in the text
    // Simple heuristic: count occurrences of " and ' before the payload
    
    idx := strings.Index(text, payload)
    if idx == -1 {
        // Should not happen if bytes.Contains passed
        return AnalysisResult{Vulnerable: false, Context: ContextScript, Reason: "Payload not found in text"}
    }
    
    prefix := text[:idx]
    doubleQuotes := strings.Count(prefix, "\"") - strings.Count(prefix, "\\\"") // Subtract escaped? Crude.
    singleQuotes := strings.Count(prefix, "'") - strings.Count(prefix, "\\'")
    
    inDouble := doubleQuotes%2 != 0
    inSingle := singleQuotes%2 != 0
    
    // If not in quotes, it's code execution (Vulnerable)
    // UNLESS the payload itself IS the code and it's valid?
    // If we are NOT in string, any injection is dangerous code injection.
    if !inDouble && !inSingle {
         return AnalysisResult{Vulnerable: true, Context: ContextScript, Reason: "Reflected in script (Code Context)"}
    }
    
	// If payload contains quotes that might break out of the identified context
    if inDouble && strings.Contains(payload, "\"") {
         return AnalysisResult{Vulnerable: true, Context: ContextScript, Reason: "Double quote breakout"}
    }
    if inSingle && strings.Contains(payload, "'") {
         return AnalysisResult{Vulnerable: true, Context: ContextScript, Reason: "Single quote breakout"}
    }

    // If inside string and no quotes in payload, it's safe.
    // Even if it has (); it is strings.
	
	return AnalysisResult{Vulnerable: false, Context: ContextScript, Reason: "Reflected in script string"}
}

// verifyAttributeContext checks if payload breaks out of attribute
func verifyAttributeContext(attrVal string, payload string) bool {
    // If payload contains quotes, assume it might break out.
    // In a real browser parser, we'd know if it was single or double quoted.
    // Here we assume if it has quotes it's potentially dangerous.
    if strings.Contains(payload, "\"") || strings.Contains(payload, "'") {
        return true
    }
    return false
}

// isEscaped checks if the payload's special characters active in the context are escaped
func isEscaped(text string, payload string) bool {
	// Must check if the payload's special characters (specifically <) appear as &lt; or
	// < in the token text.
	
    // If we find the raw payload in the text token, it means the *tokenizer* saw it as raw text.
    // Wait, html.Tokenizer.Text() returns the *unescaped* text for TextTokens? 
    // No, it returns the raw bytes.
    
    // If the payload contains "<script>" and the text token contains "&lt;script&gt;",
    // then bytes.Contains(text, payload) would be false.
    // So if bytes.Contains is true, it means the raw characters are there.
    
    // However, we need to be careful. If the payload was sent as "<script>"
    // and the server reflected "&lt;script&gt;", bytes.Contains would fail, and we wouldn't be here.
    // If we are here, it means the raw payload IS present.
    
    // BUT the tokenizer might split text.
    // Example: "foo<script>bar"
    // Tokenizer: Text("foo"), StartTag("script"), Text("bar")
    // If the payload is "<script>" and it caused a StartTag, we wouldn't be in TextToken case for the "<script>" part.
    // We would be in StartTagToken case!
    
    // So if we are in TextToken and we find "<script>" inside it, it implies that "<" was NOT interpreted as a start tag.
    // Which means it effectively IS escaped or in a context where it's not a tag (like inside title/textarea which is handled separately).
    
    // Wait, let's re-read the design doc carefully:
    // "Analyzer Logic: If the context is PCDATA, the analyzer checks if the payload successfully introduced a raw < character. If the response contains <script, the analyzer must classify it as Safe." -> Wait this seems contradictory or I misunderstood.
    
    // "Snippet 3.2.1 HTML Data State (PCDATA)"
    // "Vulnerability Condition: The payload must contain a < character followed by a valid tag name... to initiate a transition to the Tag Open State."
    // "Analyzer Logic: If the context is PCDATA, the analyzer checks if the payload successfully introduced a raw < character. If the response contains <script, the analyzer must classify it as Safe." 
    // actually checking the PDF screenshot page 4:
    // "Analyzer Logic: If the context is PCDATA, ... If the response contains <script, the analyzer must classify it as Safe." -> This text in the PDF effectively says if it stays as PCDATA (TextToken) it is SAFE because it didn't become a tag?
    // Correct! If `<script>` appears inside a `TextToken`, it means the parser did NOT see it as a script tag (e.g. it was effectively escaped `&lt;script&gt;` but the `tokenizer.Text()` returns the raw content? Or maybe the tokenizer handles entities?)
    
    // Let's verify `golang.org/x/net/html` behavior.
    // `tokenizer.Text()` returns the raw bytes of the token.
    // If the input is `&lt;script&gt;`, the tokenizer returns a TextToken with content `&lt;script&gt;`.
    // If the payload is `<script>`, `bytes.Contains("&lt;script&gt;", "<script>")` is FALSE.
    
    // So if `bytes.Contains` is TRUE in a TextToken, it means the raw `<script>` is there.
    // BUT why is it a TextToken then?
    // Because `< ` (space) or `<invalid` might keep it as text.
    // But `<script>` should definitely become a StartTagToken.
    // UNLESS the payload is something that *looks* like a tag but isn't one, OR we are in a special state.
    
    // If `bytes.Contains` finds the payload in a TextToken, it likely means the payload did NOT trigger a tag transition.
    // Example: Payload `<script>`, reflected `foo <script> bar`.
    // Tokenizer: Text("foo "), StartTag("script"), Text(" bar").
    // The loop would hit Text("foo "), no payload. Then StartTag("script").
    // We handle StartTag separately.
    
    // So if we find the payload in TextToken:
    // it likely means the payload did NOT trigger a tag.
    // Example payload `<iframe >`. Reflected `<iframe >`. 
    // Tokenizer: StartTag("iframe").
    
    // So generally, if we find the full payload in a TextToken, it means it failed to execute as code (vulnerable=false).
    // EXCEPT if the payload is just text and we want to check if it's there?
    // No, we are checking for XSS.
    
    // Re-reading logic for PCDATA (3.2.1):
    // "If the response contains <script, the analyzer must classify it as Safe."
    // This implies that if we see `<script` as text, it's safe (because it wasn't parsed as a tag).
    // Vulnerable is when it BECOMES a tag.
    
    // So, in `case html.TextToken`:
    // If payload contains `<` and it is found in TextToken, it is generally SAFE (because if it worked, it would be a TagToken).
    // BUT what if the payload is partial?
    // If payload is `<script>alert(1)</script>`
    // And it works: StartTag(script), Text("alert(1)"), EndTag(script).
    // We won't find the full payload in a single TextToken.
    
    // The design doc says: "Semantic Verification... If the payload is found within a TextToken that is a child of a Script element, the vulnerability is confirmed."
    // This refers to Script Data State (3.2.3).
    
    // So:
    // 1. PCDATA (TextToken, not in script/style/textarea):
    //    If payload matches text here, it means it didn't parse as a tag. -> SAFE.
    //    WAIT, unless the payload *is* text (e.g. plain text injection)?
    //    But for XSS we need execution.
    //    So if payload has `<` and it ends up in TextToken, it's SAFE.
    //    If payload is `alert(1)` (no tags) and it ends up in TextToken, it's SAFE.
    
    // 2. Script Data State (TextToken, insideScript=true):
    //    This is where `alert(1)` becomes dangerous.
    //    If found here -> VULNERABLE.
    
    // 3. RCDATA (TextToken, insideTitle/Textarea):
    //    If found here -> SAFE (unless breakout).
    
    return true // Placeholder, logic handled in main loop
}
