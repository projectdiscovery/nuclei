package stringslice

type RawStringSlice struct {
	StringSlice
}

func NewRawStringSlice(value interface{}) *RawStringSlice {
	return &RawStringSlice{StringSlice: StringSlice{Value: value}}
}

func (rawStringSlice *RawStringSlice) Normalize(value string) string {
	return value
}

func (rawStringSlice *RawStringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	marshalledSlice, err := marshalStringToSlice(unmarshal)
	if err != nil {
		return err
	}
	rawStringSlice.Value = marshalledSlice
	return nil
}

func (rawStringSlice RawStringSlice) JSONSchemaAlias() any {
	return StringOrSlice("")
}
