package engine

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

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
	// ActionWaitVisible waits until an element appears.
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
	ActionType ActionType
}

func (holder ActionTypeHolder) String() string {
	return holder.ActionType.String()
}
func (holder ActionTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "action to perform",
		Description: "Type of actions to perform,enum=navigate,enum=script,enum=click,enum=rightclick,enum=text,enum=screenshot,enum=time,enum=select,enum=files,enum=waitload,enum=getresource,enum=extract,enum=setmethod,enum=addheader,enum=setheader,enum=deleteheader,enum=setbody,enum=waitevent,enum=keyboard,enum=debug,enum=sleep",
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

func (holder *ActionTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.ActionType.String())
}

func (holder ActionTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.ActionType.String(), nil
}
