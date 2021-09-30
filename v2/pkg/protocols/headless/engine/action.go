package engine

import "strings"

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
	// ActionKeyboard performs a keyboard action event on a page.
	ActionKeyboard
	// ActionDebug debug slows down headless and adds a sleep to each page.
	ActionDebug
	// ActionSleep executes a sleep for a specified duration
	ActionSleep
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
	"keyboard":     ActionKeyboard,
	"debug":        ActionDebug,
	"sleep":        ActionSleep,
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
	ActionKeyboard:     "keyboard",
	ActionDebug:        "debug",
	ActionSleep:        "sleep",
}

// Action is an action taken by the browser to reach a navigation
//
// Each step that the browser executes is an action. Most navigations
// usually start from the ActionLoadURL event, and further navigations
// are discovered on the found page. We also keep track and only
// scrape new navigation from pages we haven't crawled yet.
type Action struct {
	// description:
	//   Args contain arguments for the headless action.
	//
	//   Per action arguments are described in detail [here](https://nuclei.projectdiscovery.io/templating-guide/protocols/headless/).
	Data map[string]string `yaml:"args,omitempty" jsonschema:"title=arguments for headless action,description=Args contain arguments for the headless action"`
	// description: |
	//   Name is the name assigned to the headless action.
	//
	//   This can be used to execute code, for instance in browser
	//   DOM using script action, and get the result in a variable
	//   which can be matched upon by nuclei. An Example template [here](https://github.com/projectdiscovery/nuclei-templates/blob/master/headless/prototype-pollution-check.yaml).
	Name string `yaml:"name,omitempty" jsonschema:"title=name for headless action,description=Name is the name assigned to the headless action"`
	// description: |
	//   Description is the optional description of the headless action
	Description string `yaml:"description,omitempty" jsonschema:"title=description for headless action,description=Description of the headless action"`
	// description: |
	//   Action is the type of the action to perform.
	// values:
	//   - "navigate"
	//   - "script"
	//   - "click"
	//   - "rightclick"
	//   - "text"
	//   - "screenshot"
	//   - "time"
	//   - "select"
	//   - "files"
	//   - "waitload"
	//   - "getresource"
	//   - "extract"
	//   - "setmethod"
	//   - "addheader"
	//   - "setheader"
	//   - "deleteheader"
	//   - "setbody"
	//   - "waitevent"
	//   - "keyboard"
	//   - "debug"
	//   - "sleep"
	ActionType string `yaml:"action" jsonschema:"title=action to perform,description=Type of actions to perform,enum=navigate,enum=script,enum=click,enum=rightclick,enum=text,enum=screenshot,enum=time,enum=select,enum=files,enum=waitload,enum=getresource,enum=extract,enum=setmethod,enum=addheader,enum=setheader,enum=deleteheader,enum=setbody,enum=waitevent,enum=keyboard,enum=debug,enum=sleep"`
}

// String returns the string representation of an action
func (a *Action) String() string {
	builder := &strings.Builder{}
	builder.WriteString(a.ActionType)
	if a.Name != "" {
		builder.WriteString(" Name:")
		builder.WriteString(a.Name)
	}
	builder.WriteString(" ")
	for k, v := range a.Data {
		builder.WriteString(k)
		builder.WriteString(":")
		builder.WriteString(v)
		builder.WriteString(",")
	}
	return strings.TrimSuffix(builder.String(), ",")
}

// GetArg returns an arg for a name
func (a *Action) GetArg(name string) string {
	v, ok := a.Data[name]
	if !ok {
		return ""
	}
	return v
}
