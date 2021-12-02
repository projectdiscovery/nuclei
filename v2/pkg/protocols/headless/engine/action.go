package engine

import "strings"

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
	ActionType ActionTypeHolder `yaml:"action" jsonschema:"title=action to perform,description=Type of actions to perform,enum=navigate,enum=script,enum=click,enum=rightclick,enum=text,enum=screenshot,enum=time,enum=select,enum=files,enum=waitload,enum=getresource,enum=extract,enum=setmethod,enum=addheader,enum=setheader,enum=deleteheader,enum=setbody,enum=waitevent,enum=keyboard,enum=debug,enum=sleep"`
}

// String returns the string representation of an action
func (a *Action) String() string {
	builder := &strings.Builder{}
	builder.WriteString(a.ActionType.String())
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
