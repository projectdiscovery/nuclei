package stringslice

type RawStringSlice struct {
	StringSlice
}

func NewRaw(value interface{}) RawStringSlice {
	return RawStringSlice{StringSlice: StringSlice{Value: value}}
}

func NewPointer(value interface{}) *RawStringSlice {
	s := NewRaw(value)
	return &s
}

func (rawStringSlice RawStringSlice) Normalize(value string) string {
	return value
}
