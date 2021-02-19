package engine

// ActionType defines the action type for a browser action
type ActionType int8

// Types to be executed by the user.
const (
	// ActionNavigate performs a navigation to the specified URL
	// URL can include nuclei payload data such as URL, Hostname, etc.
	ActionNavigate ActionType = iota + 1
	// ActionScript executes a JS snippet on the page.
	ActionScript
	// ActionClick performs the left-click action on an Element.
	ActionClick
	// ActionRightClick performs the right-click action on an Element.
	ActionRightClick
	// ActionTextInput performs an action for a text input
	ActionTextInput
	// ActionScreenshot performs the screenshot action writing to a file.
	ActionScreenshot
	// ActionTimeInput performs an action on a time input.
	ActionTimeInput
	// ActionSelectInput performs an action on a select input.
	ActionSelectInput
	// ActionFilesInput performs an action on a file input.
	ActionFilesInput
	// ActionWaitLoad waits for the page to stop loading.
	ActionWaitLoad
	// ActionGetResource performs a get resource action on an element
	ActionGetResource
	// ActionExtract performs an extraction on an element
	ActionExtract
	// ActionSetMethod sets the request method
	ActionSetMethod
	// ActionAddHeader adds a header to the request
	ActionAddHeader
	// ActionSetHeader sets a header in the request
	ActionSetHeader
	// ActionDeleteHeader deletes a header from the request
	ActionDeleteHeader
	// ActionSetBody sets the value of the request body
	ActionSetBody
	// ActionWaitEvent waits for a specific event.
	ActionWaitEvent
)

// ActionStringToAction converts an action from string to internal representation
var ActionStringToAction = map[string]ActionType{
	"navigate":     ActionNavigate,
	"script":       ActionScript,
	"click":        ActionClick,
	"rightclick":   ActionRightClick,
	"text":         ActionTextInput,
	"screenshot":   ActionScreenshot,
	"time":         ActionTimeInput,
	"select":       ActionSelectInput,
	"files":        ActionFilesInput,
	"waitload":     ActionWaitLoad,
	"getresource":  ActionGetResource,
	"extract":      ActionExtract,
	"setmethod":    ActionSetMethod,
	"addheader":    ActionAddHeader,
	"setheader":    ActionSetHeader,
	"deleteheader": ActionDeleteHeader,
	"setbody":      ActionSetBody,
	"waitevent":    ActionWaitEvent,
}

// ActionToActionString converts an action from  internal representation to string
var ActionToActionString = map[ActionType]string{
	ActionNavigate:     "navigate",
	ActionScript:       "script",
	ActionClick:        "click",
	ActionRightClick:   "rightclick",
	ActionTextInput:    "text",
	ActionScreenshot:   "screenshot",
	ActionTimeInput:    "time",
	ActionSelectInput:  "select",
	ActionFilesInput:   "files",
	ActionWaitLoad:     "waitload",
	ActionGetResource:  "getresource",
	ActionExtract:      "extract",
	ActionSetMethod:    "set-method",
	ActionAddHeader:    "addheader",
	ActionSetHeader:    "setheader",
	ActionDeleteHeader: "deleteheader",
	ActionSetBody:      "setbody",
	ActionWaitEvent:    "waitevent",
}

// Action is an action taken by the browser to reach a navigation
//
// Each step that the browser executes is an action. Most navigations
// usually start from the ActionLoadURL event, and further navigations
// are discovered on the found page. We also keep track and only
// scrape new navigation from pages we haven't crawled yet.
type Action struct {
	Data       map[string]string
	Name       string
	ActionType ActionType
}

// GetArg returns an arg for a name
func (a *Action) GetArg(name string) string {
	v, ok := a.Data[name]
	if !ok {
		return ""
	}
	return v
}
