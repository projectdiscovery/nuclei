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
