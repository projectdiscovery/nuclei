package userAgent

import (
	"encoding/json"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/pkg/errors"
)

type UserAgent int

// name:UserAgent
const (
	// name:random
	Random UserAgent = iota
	// name:off
	Off
	// name:default
	Default
	// name:custom
	Custom
	limit
)

var userAgentMappings = map[UserAgent]string{
	Random:  "random",
	Off:     "off",
	Default: "default",
	Custom:  "custom",
}

func GetSupportedUserAgentOptions() []UserAgent {
	var result []UserAgent
	for index := UserAgent(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toUserAgent(valueToMap string) (UserAgent, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range userAgentMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid userAgent: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (userAgent UserAgent) String() string {
	return userAgentMappings[userAgent]
}

// UserAgentHolder holds a UserAgent type. Required for un/marshalling purposes
type UserAgentHolder struct {
	Value UserAgent `mapping:"true"`
}

func (userAgentHolder UserAgentHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "userAgent for the headless",
		Description: "userAgent for the headless http request",
	}
	for _, userAgent := range GetSupportedUserAgentOptions() {
		gotType.Enum = append(gotType.Enum, userAgent.String())
	}
	return gotType
}

func (userAgentHolder *UserAgentHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledUserAgent string
	if err := unmarshal(&marshalledUserAgent); err != nil {
		return err
	}
	computedUserAgent, err := toUserAgent(marshalledUserAgent)
	if err != nil {
		return err
	}
	userAgentHolder.Value = computedUserAgent
	return nil
}

func (userAgentHolder *UserAgentHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedUserAgent, err := toUserAgent(s)
	if err != nil {
		return err
	}

	userAgentHolder.Value = computedUserAgent
	return nil
}

func (userAgentHolder *UserAgentHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(userAgentHolder.Value.String())
}

func (userAgentHolder UserAgentHolder) MarshalYAML() (interface{}, error) {
	return userAgentHolder.Value.String(), nil
}
