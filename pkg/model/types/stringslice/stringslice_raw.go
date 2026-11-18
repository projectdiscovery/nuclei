package stringslice

type RawStringSlice struct {
	StringSlice
}

func NewRawStringSlice(value interface{}) *RawStringSlice {
	return &RawStringSlice{StringSlice: StringSlice{Value: value}}
}

// String is nil-safe: model.Info.Reference is nil for templates without
// references, and the promoted StringSlice.String would dereference it.
func (rawStringSlice *RawStringSlice) String() string {
	if rawStringSlice == nil {
		return ""
	}
	return rawStringSlice.StringSlice.String()
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
