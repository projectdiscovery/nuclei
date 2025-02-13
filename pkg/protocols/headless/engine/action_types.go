package engine

import (
	"errors"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// ActionType defines the action type for a browser action
type ActionType int8

// ActionData stores the action output data
type ActionData = mapsutil.Map[string, any]

// Types to be executed by the user.
// name:ActionType
const (
	// ActionNavigate performs a navigation to the specified URL
	// name:navigate
	ActionNavigate ActionType = iota + 1
	// ActionScript executes a JS snippet on the page.
	// name:script
	ActionScript
	// ActionClick performs the left-click action on an Element.
	// name:click
	ActionClick
	// ActionRightClick performs the right-click action on an Element.
	// name:rightclick
	ActionRightClick
	// ActionTextInput performs an action for a text input
	// name:text
	ActionTextInput
	// ActionScreenshot performs the screenshot action writing to a file.
	// name:screenshot
	ActionScreenshot
	// ActionTimeInput performs an action on a time input.
	// name:time
	ActionTimeInput
	// ActionSelectInput performs an action on a select input.
	// name:select
	ActionSelectInput
	// ActionFilesInput performs an action on a file input.
	// name:files
	ActionFilesInput
	// ActionWaitDOM waits for the HTML document has been completely loaded & parsed.
	// name:waitdom
	ActionWaitDOM
	// ActionWaitFCP waits for the first piece of content (text, image, etc.) is painted on the screen.
	// name:waitfcp
	ActionWaitFCP
	// ActionWaitFMP waits for page has rendered enough meaningful content to be useful to the user.
	// name:waitfmp
	ActionWaitFMP
	// ActionWaitIdle waits for the network is completely idle (no ongoing network requests).
	// name:waitidle
	ActionWaitIdle
	// ActionWaitLoad waits for the page and all its resources (like stylesheets and images) have finished loading.
	// name:waitload
	ActionWaitLoad
	// ActionWaitStable waits until the page is stable.
	// name:waitstable
	ActionWaitStable
	// ActionGetResource performs a get resource action on an element
	// name:getresource
	ActionGetResource
	// ActionExtract performs an extraction on an element
	// name:extract
	ActionExtract
	// ActionSetMethod sets the request method
	// name:setmethod
	ActionSetMethod
	// ActionAddHeader adds a header to the request
	// name:addheader
	ActionAddHeader
	// ActionSetHeader sets a header in the request
	// name:setheader
	ActionSetHeader
	// ActionDeleteHeader deletes a header from the request
	// name:deleteheader
	ActionDeleteHeader
	// ActionSetBody sets the value of the request body
	// name:setbody
	ActionSetBody
	// ActionWaitEvent waits for a specific event.
	// name:waitevent
	ActionWaitEvent
	// ActionWaitDialog waits for JavaScript dialog (alert, confirm, prompt, or onbeforeunload).
	// name:dialog
	ActionWaitDialog
	// ActionKeyboard performs a keyboard action event on a page.
	// name:keyboard
	ActionKeyboard
	// ActionDebug debug slows down headless and adds a sleep to each page.
	// name:debug
	ActionDebug
	// ActionSleep executes a sleep for a specified duration
	// name:sleep
	ActionSleep
	// ActionWaitVisible waits until an element appears.
	// name:waitvisible
	ActionWaitVisible
	// limit
	limit
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
	"waitdom":      ActionWaitDOM,
	"waitfcp":      ActionWaitFCP,
	"waitfmp":      ActionWaitFMP,
	"waitidle":     ActionWaitIdle,
	"waitload":     ActionWaitLoad,
	"waitstable":   ActionWaitStable,
	"getresource":  ActionGetResource,
	"extract":      ActionExtract,
	"setmethod":    ActionSetMethod,
	"addheader":    ActionAddHeader,
	"setheader":    ActionSetHeader,
	"deleteheader": ActionDeleteHeader,
	"setbody":      ActionSetBody,
	"waitevent":    ActionWaitEvent,
	"waitdialog":   ActionWaitDialog,
	"keyboard":     ActionKeyboard,
	"debug":        ActionDebug,
	"sleep":        ActionSleep,
	"waitvisible":  ActionWaitVisible,
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
	ActionWaitDOM:      "waitdom",
	ActionWaitFCP:      "waitfcp",
	ActionWaitFMP:      "waitfmp",
	ActionWaitIdle:     "waitidle",
	ActionWaitLoad:     "waitload",
	ActionWaitStable:   "waitstable",
	ActionGetResource:  "getresource",
	ActionExtract:      "extract",
	ActionSetMethod:    "setmethod",
	ActionAddHeader:    "addheader",
	ActionSetHeader:    "setheader",
	ActionDeleteHeader: "deleteheader",
	ActionSetBody:      "setbody",
	ActionWaitEvent:    "waitevent",
	ActionWaitDialog:   "waitdialog",
	ActionKeyboard:     "keyboard",
	ActionDebug:        "debug",
	ActionSleep:        "sleep",
	ActionWaitVisible:  "waitvisible",
}

// GetSupportedActionTypes returns list of supported types
func GetSupportedActionTypes() []ActionType {
	var result []ActionType
	for index := ActionType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toActionTypes(valueToMap string) (ActionType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range ActionToActionString {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid action type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (t ActionType) String() string {
	return ActionToActionString[t]
}

// ActionTypeHolder is used to hold internal type of the action
type ActionTypeHolder struct {
	ActionType ActionType `mapping:"true"`
}

func (holder ActionTypeHolder) String() string {
	return holder.ActionType.String()
}
func (holder ActionTypeHolder) JSONSchema() *jsonschema.Schema {
	gotType := &jsonschema.Schema{
		Type:        "string",
		Title:       "action to perform",
		Description: "Type of actions to perform",
	}
	for _, types := range GetSupportedActionTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *ActionTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toActionTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.ActionType = computedType
	return nil
}

func (holder *ActionTypeHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedType, err := toActionTypes(s)
	if err != nil {
		return err
	}

	holder.ActionType = computedType
	return nil
}

func (holder *ActionTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.ActionType.String())
}

func (holder ActionTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.ActionType.String(), nil
}
