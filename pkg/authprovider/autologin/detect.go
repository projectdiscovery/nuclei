// Package autologin implements turnkey form-based authentication for nuclei's
// authenticated scanning. Instead of requiring a hand-written auth template that
// performs the login and extracts a token, the caller supplies only a login URL
// and credentials; this package fetches the login page, auto-detects the login
// form (username/password fields plus any hidden CSRF tokens), submits the
// credentials and captures the resulting session.
//
// detect.go contains the pure, network-free form-detection logic so it can be
// unit-tested in isolation from the HTTP engine in login.go.
package autologin

import (
	"net/url"
	"strings"

	"github.com/projectdiscovery/utils/errkit"
	"golang.org/x/net/html"
)

var (
	// ErrNoLoginForm is returned when the page contains no form with a password
	// field (the minimal signal that a form is a credential-login form).
	ErrNoLoginForm = errkit.New("no login form (password field) found on page")
)

// LoginForm describes a detected HTML login form and everything needed to
// submit it.
type LoginForm struct {
	// Action is the absolute URL the form submits to, resolved against the page URL.
	Action string
	// Method is the upper-cased HTTP method ("POST" or "GET").
	Method string
	// EncType is the form encoding ("application/x-www-form-urlencoded" or
	// "multipart/form-data"); empty means the urlencoded default.
	EncType string
	// UsernameField is the name of the input that should receive the username.
	// It may be empty when no plausible username field is present (e.g. a
	// password-only or token form), in which case the caller may still submit.
	UsernameField string
	// PasswordField is the name of the password input. Always non-empty on a
	// successfully detected form.
	PasswordField string
	// Fields holds extra form values that must be submitted verbatim — most
	// importantly hidden inputs carrying CSRF tokens, plus any pre-filled
	// defaults and a named submit button. Username/password are NOT included
	// here; the engine fills those into UsernameField/PasswordField.
	Fields map[string]string
}

// usernameHintTokens are substrings (matched case-insensitively against an
// input's name/id/autocomplete) that strongly suggest a username/identifier
// field. Ordered roughly by specificity.
var usernameHintTokens = []string{"username", "user", "email", "e-mail", "login", "account", "userid", "uid", "identifier", "phone"}

// DetectLoginForm parses the given HTML page body and returns the best
// credential-login form found on it. pageURL is the absolute URL the body was
// fetched from and is used to resolve relative form actions. It returns
// ErrNoLoginForm if no form containing a password field exists.
func DetectLoginForm(body string, pageURL *url.URL) (*LoginForm, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, errkit.Wrap(err, "failed to parse html")
	}

	var forms []*html.Node
	collectForms(doc, &forms)

	var best *LoginForm
	bestScore := -1
	for _, formNode := range forms {
		candidate, score := buildLoginForm(formNode, pageURL)
		if candidate == nil {
			continue
		}
		// Prefer the highest-scoring form, keeping the first on ties so document
		// order acts as the tie-breaker.
		if score > bestScore {
			best = candidate
			bestScore = score
		}
	}
	if best == nil {
		return nil, ErrNoLoginForm
	}
	return best, nil
}

// collectForms walks the parse tree depth-first and appends every <form> node.
func collectForms(n *html.Node, out *[]*html.Node) {
	if n.Type == html.ElementNode && n.Data == "form" {
		*out = append(*out, n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectForms(c, out)
	}
}

// fieldNode is a flattened view of a form control relevant to login detection.
type fieldNode struct {
	tag      string // input, select, textarea, button
	typ      string // lower-cased type attribute (inputs)
	name     string
	id       string
	value    string
	autoComp string // autocomplete attribute
}

// buildLoginForm inspects a single <form> node and, if it looks like a
// credential-login form (contains exactly one usable password field), returns a
// populated LoginForm together with a heuristic score used to pick the best
// form on a page. A nil form means "not a login form".
func buildLoginForm(formNode *html.Node, pageURL *url.URL) (*LoginForm, int) {
	var fields []fieldNode
	collectFields(formNode, &fields)

	// Locate the password field. A form with no password field is not a
	// credential-login form; a form with several password fields is almost
	// always a registration / change-password form, so we skip it.
	passwordIdx := -1
	passwordCount := 0
	for i, f := range fields {
		if f.tag == "input" && f.typ == "password" {
			passwordCount++
			if passwordIdx == -1 {
				passwordIdx = i
			}
		}
	}
	if passwordIdx == -1 || passwordCount > 1 {
		return nil, 0
	}
	password := fields[passwordIdx]
	if password.name == "" {
		// A password field with no name cannot be submitted.
		return nil, 0
	}

	form := &LoginForm{
		Method:        resolveMethod(formNode),
		EncType:       strings.ToLower(strings.TrimSpace(getAttr(formNode, "enctype"))),
		PasswordField: password.name,
		Fields:        map[string]string{},
	}
	form.Action = resolveAction(formNode, pageURL)

	usernameIdx := pickUsernameField(fields, passwordIdx)
	if usernameIdx >= 0 {
		form.UsernameField = fields[usernameIdx].name
	}

	// Carry along hidden inputs (CSRF tokens etc.), pre-filled defaults and a
	// single named submit button, but never the username/password controls.
	submitAdded := false
	for i, f := range fields {
		if i == passwordIdx || i == usernameIdx || f.name == "" {
			continue
		}
		switch {
		case f.tag == "input" && f.typ == "hidden":
			form.Fields[f.name] = f.value
		case f.tag == "input" && (f.typ == "submit" || f.typ == "image"):
			// Many backends key off the submit button name; include the first one.
			if !submitAdded && f.value != "" {
				form.Fields[f.name] = f.value
				submitAdded = true
			}
		case f.tag == "button" && (f.typ == "submit" || f.typ == ""):
			if !submitAdded && f.value != "" {
				form.Fields[f.name] = f.value
				submitAdded = true
			}
		case f.value != "" && f.typ != "checkbox" && f.typ != "radio":
			// Preserve pre-filled defaults for other text-like inputs so we don't
			// drop values the server expects.
			form.Fields[f.name] = f.value
		}
	}

	// Score: a real login form usually has both a username and a password field;
	// CSRF/hidden tokens raise confidence further. This lets DetectLoginForm
	// prefer the actual login form over, say, a newsletter box that happens to
	// share the page.
	score := 1
	if form.UsernameField != "" {
		score += 2
	}
	if len(form.Fields) > 0 {
		score++
	}
	return form, score
}

// collectFields flattens the form controls within a form node in document order.
func collectFields(n *html.Node, out *[]fieldNode) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			switch c.Data {
			case "input", "select", "textarea", "button":
				*out = append(*out, fieldNode{
					tag:      c.Data,
					typ:      strings.ToLower(strings.TrimSpace(getAttr(c, "type"))),
					name:     getAttr(c, "name"),
					id:       getAttr(c, "id"),
					value:    getAttr(c, "value"),
					autoComp: strings.ToLower(strings.TrimSpace(getAttr(c, "autocomplete"))),
				})
			}
		}
		collectFields(c, out)
	}
}

// pickUsernameField selects the most likely username/identifier field. It
// considers only text-like inputs appearing before the password field and
// prefers ones whose name/id/autocomplete match a known hint token; otherwise
// it falls back to the closest text-like input preceding the password.
func pickUsernameField(fields []fieldNode, passwordIdx int) int {
	isCandidate := func(f fieldNode) bool {
		if f.tag != "input" {
			return false
		}
		switch f.typ {
		case "", "text", "email", "tel", "search":
			return f.name != ""
		default:
			return false
		}
	}

	// First pass: hint-token match among candidates preceding the password field.
	bestHint := -1
	bestHintRank := len(usernameHintTokens)
	for i := 0; i < passwordIdx; i++ {
		f := fields[i]
		if !isCandidate(f) {
			continue
		}
		hay := strings.ToLower(f.name + " " + f.id + " " + f.autoComp)
		for rank, tok := range usernameHintTokens {
			if strings.Contains(hay, tok) && rank < bestHintRank {
				bestHint = i
				bestHintRank = rank
			}
		}
	}
	if bestHint >= 0 {
		return bestHint
	}

	// Second pass: closest text-like input before the password field.
	for i := passwordIdx - 1; i >= 0; i-- {
		if isCandidate(fields[i]) {
			return i
		}
	}

	// Last resort: first text-like input anywhere in the form (covers oddly
	// ordered markup where the username sits after the password).
	for i := range fields {
		if i == passwordIdx {
			continue
		}
		if isCandidate(fields[i]) {
			return i
		}
	}
	return -1
}

// resolveMethod returns the upper-cased form method, defaulting to POST. The
// HTML default is GET, but credential-login forms virtually always POST, and a
// GET login would leak credentials into the URL/query — so for an autonomous
// login submitter POST is the safer default when unspecified.
func resolveMethod(formNode *html.Node) string {
	m := strings.ToUpper(strings.TrimSpace(getAttr(formNode, "method")))
	if m == "" {
		return "POST"
	}
	return m
}

// resolveAction resolves the form action against the page URL. An empty/missing
// action submits back to the page itself.
func resolveAction(formNode *html.Node, pageURL *url.URL) string {
	action := strings.TrimSpace(getAttr(formNode, "action"))
	if action == "" {
		if pageURL != nil {
			return pageURL.String()
		}
		return ""
	}
	if pageURL == nil {
		return action
	}
	ref, err := url.Parse(action)
	if err != nil {
		return action
	}
	return pageURL.ResolveReference(ref).String()
}

// getAttr returns the value of the named attribute (case-insensitive) on an
// element node, or "" if absent.
func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}
