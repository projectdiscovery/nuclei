package autologin

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/utils/errkit"
)

// recordingFile is the Chrome DevTools Recorder / @puppeteer/replay export
// schema (the two are identical). A user records their real login in Chrome
// (DevTools -> Recorder) and exports it as JSON; we compile it down to the same
// LoginStep list the headless engine already replays, so complex SSO/MFA logins
// can be authored by recording instead of hand-writing steps or templates.
type recordingFile struct {
	Title string          `json:"title"`
	Steps []recordingStep `json:"steps"`
}

// recordingStep is a single recorded user action. Selectors is a list of
// alternative selector strategies for the target element, each itself a list
// (Chrome groups shadow/frame piercing selectors); we use the first entry of
// each group as a candidate.
type recordingStep struct {
	Type       string     `json:"type"`
	URL        string     `json:"url"`
	Selectors  [][]string `json:"selectors"`
	Value      string     `json:"value"`
	Key        string     `json:"key"`
	Target     string     `json:"target"`
	Expression string     `json:"expression"`
}

// StepsFromRecordingFile reads and converts a recorder export file into
// LoginSteps. username/password are used to parameterize the recording so the
// captured credential literals are replaced with {{username}}/{{password}}
// placeholders (kept out of the committed flow file).
func StepsFromRecordingFile(path, username, password string) ([]LoginStep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errkit.Wrap(err, "auto-login: failed to read recording file")
	}
	return StepsFromRecording(data, username, password)
}

// StepsFromRecording converts a recorder export (JSON) into LoginSteps.
func StepsFromRecording(data []byte, username, password string) ([]LoginStep, error) {
	var rec recordingFile
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, errkit.Wrap(err, "auto-login: invalid recording json")
	}
	if len(rec.Steps) == 0 {
		return nil, errkit.New("auto-login: recording contains no steps")
	}

	var steps []LoginStep
	for _, rs := range rec.Steps {
		switch strings.ToLower(strings.TrimSpace(rs.Type)) {
		case "navigate":
			if rs.URL != "" {
				steps = append(steps, LoginStep{Action: "navigate", Value: rs.URL})
			}
		case "click", "doubleclick":
			sel := pickSelector(rs.Selectors)
			if sel == "" {
				continue
			}
			steps = append(steps, LoginStep{Action: "click", Selector: sel})
		case "change":
			sel := pickSelector(rs.Selectors)
			if sel == "" {
				continue
			}
			steps = append(steps, LoginStep{
				Action:   "fill",
				Selector: sel,
				Value:    parameterizeValue(rs.Value, sel, username, password),
			})
		case "keydown":
			// Only emit actionable keys; character keys are captured by `change`,
			// and the paired keyUp event is ignored to avoid double submission.
			if key := normalizeKey(rs.Key); key != "" {
				steps = append(steps, LoginStep{Action: "press", Value: key, Selector: pickSelector(rs.Selectors)})
			}
		case "waitforelement":
			sel := pickSelector(rs.Selectors)
			if sel == "" {
				continue
			}
			steps = append(steps, LoginStep{Action: "waitvisible", Selector: sel})
		case "waitforexpression":
			// We can't evaluate arbitrary expressions in the step engine; fall back
			// to a settle wait so the page can reach the expected state.
			steps = append(steps, LoginStep{Action: "wait"})
		case "setviewport", "keyup", "scroll", "close", "emulatenetworkconditions", "hover", "":
			// Not relevant to (or not supported for) headless login replay.
			continue
		default:
			// Unknown step types are skipped rather than failing the whole import.
			continue
		}
	}

	if len(steps) == 0 {
		return nil, errkit.New("auto-login: recording produced no replayable steps")
	}
	return steps, nil
}

// FirstNavigateURL returns the URL of the first navigate step in a recording, or
// "" if none. It lets the caller derive the login URL from the recording.
func FirstNavigateURL(steps []LoginStep) string {
	for _, s := range steps {
		if strings.EqualFold(s.Action, "navigate") && s.Value != "" {
			return s.Value
		}
	}
	return ""
}

// normalizeKey maps recorder key names to the engine's supported press keys.
// Character keys (length 1) return "" because the text they produce is already
// captured by `change` steps.
func normalizeKey(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "enter", "return", "numpadenter":
		return "enter"
	case "tab":
		return "tab"
	case "escape", "esc":
		return "escape"
	case "space":
		return "space"
	default:
		return ""
	}
}

// parameterizeValue replaces a recorded credential literal with a placeholder so
// secrets never live in the recording file. It masks by exact match against the
// configured credentials and, defensively, masks any value typed into a field
// whose selector looks like a password input.
func parameterizeValue(value, selector, username, password string) string {
	if password != "" && value == password {
		return "{{password}}"
	}
	if username != "" && value == username {
		return "{{username}}"
	}
	if looksLikePasswordSelector(selector) {
		return "{{password}}"
	}
	return value
}

func looksLikePasswordSelector(selector string) bool {
	s := strings.ToLower(selector)
	return strings.Contains(s, "password") || strings.Contains(s, "passwd") || strings.Contains(s, "type=\"password\"") || strings.Contains(s, "type=password")
}

// pickSelector chooses the most engine-friendly selector from the recorder's
// alternatives, preferring native CSS, then XPath, then an aria-label CSS
// approximation, then a text-content XPath. Shadow-piercing (pierce/) selectors
// are skipped because the engine cannot resolve them.
func pickSelector(groups [][]string) string {
	var css, xpath, aria, text string
	for _, group := range groups {
		for _, s := range group {
			s = strings.TrimSpace(s)
			switch {
			case s == "":
				continue
			case strings.HasPrefix(s, "xpath/"):
				if xpath == "" {
					xpath = "xpath=" + strings.TrimPrefix(s, "xpath/")
				}
			case strings.HasPrefix(s, "aria/"):
				if aria == "" {
					aria = ariaToCSS(strings.TrimPrefix(s, "aria/"))
				}
			case strings.HasPrefix(s, "text/"):
				if text == "" {
					text = textToXPath(strings.TrimPrefix(s, "text/"))
				}
			case strings.HasPrefix(s, "pierce/"):
				continue
			default:
				if css == "" {
					css = s
				}
			}
		}
	}
	for _, candidate := range []string{css, xpath, aria, text} {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

// ariaToCSS approximates an accessibility-name selector as an aria-label CSS
// attribute selector. It is best-effort; recordings usually also carry a CSS or
// XPath selector that is preferred over this.
func ariaToCSS(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, `"`) {
		return ""
	}
	return fmt.Sprintf(`[aria-label="%s"]`, name)
}

// textToXPath converts a text-content selector into an XPath the engine can run.
func textToXPath(t string) string {
	t = strings.TrimSpace(t)
	if t == "" || strings.Contains(t, `"`) {
		return ""
	}
	return fmt.Sprintf(`xpath=//*[contains(normalize-space(.), "%s")]`, t)
}
