package structs

import (
	"testing"

	"github.com/dop251/goja"
)

func TestStructsJSPack(t *testing.T) {
	cases := []struct {
		f    string
		a    []interface{}
		want []byte
		e    bool
	}{
		//	{
		//		"structs.pack('??', [true, false]);", nil, []byte{1, 0}, false,
		//	},
		//		{
		//			"structs.pack('hhh', [0, 5, -5]);", nil, []byte{0, 0, 5, 0, 251, 255}, false,
		//		},
		//	{
		//		"structs.pack('1s2s10s', ['a', 'bb', '1234567890']);", nil, []byte{97, 98, 98, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48}, false,
		//	},
	}
	for _, tt := range cases {
		runtime := goja.New()
		module := &Module{}
		module.Enable(runtime)

		value, err := runtime.RunString(tt.f)
		if err != nil {
			t.Errorf("StructsJSPack() error f = %v = %v", tt.f, err)
			continue
		}
		got := value.Export().([]byte)
		if len(got) != len(tt.want) {
			t.Errorf("StructsJSPack() = %v, want %v", got, tt.want)
		}
		if got[0] != tt.want[0] {
			t.Errorf("StructsJSPack() = %v, want %v", got, tt.want)
		}

	}
}

func TestStructsPack(t *testing.T) {
	cases := []struct {
		f    string
		a    []interface{}
		want []byte
		e    bool
	}{
		{"??", []interface{}{true, false}, []byte{1, 0}, false},
		{"hhh", []interface{}{0, 5, -5},
			[]byte{0, 0, 5, 0, 251, 255}, false},
		{"HHH", []interface{}{0, 5, 2300}, []byte{0, 0, 5, 0, 252, 8}, false},
		{"iii", []interface{}{0, 5, -5},
			[]byte{0, 0, 0, 0, 5, 0, 0, 0, 251, 255, 255, 255}, false},
		{"III", []interface{}{0, 5, 2300},
			[]byte{0, 0, 0, 0, 5, 0, 0, 0, 252, 8, 0, 0}, false},
		{"fff", []interface{}{float32(0.0), float32(5.3), float32(-5.3)},
			[]byte{0, 0, 0, 0, 154, 153, 169, 64, 154, 153, 169, 192}, false},
		{"ddd", []interface{}{0.0, 5.3, -5.3},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 51, 51, 51, 51, 51, 51, 21, 64, 51, 51, 51, 51, 51, 51, 21, 192}, false},
		{"1s2s10s", []interface{}{"a", "bb", "1234567890"},
			[]byte{97, 98, 98, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48}, false},
		{"III4s", []interface{}{1, 2, 4, "DUMP"},
			[]byte{1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 68, 85, 77, 80}, false},
	}
	for _, tt := range cases {
		got, err := StructsPack(tt.f, tt.a)
		if (err != nil) != tt.e {
			t.Errorf("%q. StructsPack() error = %v, wantErr %v", tt.f, err, tt.e)
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("%q. StructsPack() = %v, want %v", tt.f, got, tt.want)
		}
	}
}

func TestStructsUnpack(t *testing.T) {
	cases := []struct {
		f    string
		a    []byte
		want []interface{}
		e    bool
	}{
		{"??", []byte{1, 0}, []interface{}{true, false}, false},
		{"hhh", []byte{0, 0, 5, 0, 251, 255},
			[]interface{}{0, 5, -5}, false},
		{"HHH", []byte{0, 0, 5, 0, 252, 8},
			[]interface{}{0, 5, 2300}, false},
		{"iii", []byte{0, 0, 0, 0, 5, 0, 0, 0, 251, 255, 255, 255},
			[]interface{}{0, 5, -5}, false},
		{"III", []byte{0, 0, 0, 0, 5, 0, 0, 0, 252, 8, 0, 0},
			[]interface{}{0, 5, 2300}, false},
		{"fff",
			[]byte{0, 0, 0, 0, 154, 153, 169, 64, 154, 153, 169, 192},
			[]interface{}{float32(0.0), float32(5.3), float32(-5.3)}, false},
		{"ddd",
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 51, 51, 51, 51, 51, 51, 21, 64, 51, 51, 51, 51, 51, 51, 21, 192},
			[]interface{}{0.0, 5.3, -5.3}, false},
		{"1s2s10s",
			[]byte{97, 98, 98, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48},
			[]interface{}{"a", "bb", "1234567890"}, false},
		{"III4s",
			[]byte{1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 68, 85, 77, 80},
			[]interface{}{1, 2, 4, "DUMP"}, false},
	}

	for _, tt := range cases {
		got, err := StructsUnpack(tt.f, tt.a)
		if (err != nil) != tt.e {
			t.Errorf("%q. StructsUnpack() error = %v, wantErr %v", tt.f, err, tt.e)
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("%q. StructsUnpack() = %v, want %v", tt.f, got, tt.want)
		}
	}
}

func Test_buildFormatStringSliceFromString(t *testing.T) {
	cases := []struct {
		f    string
		want []string
	}{
		{"??", []string{"?", "?"}},
		{"hhh", []string{"h", "h", "h"}},
		{"1s2s10s", []string{"1s", "2s", "10s"}},
		{"III4s", []string{"I", "I", "I", "4s"}},
	}
	for _, tt := range cases {
		got := buildFormatSliceFromStringFormat(tt.f)
		if len(got) != len(tt.want) {
			t.Fatalf("%q. buildFormatStringSliceFromString() = %v, want %v", tt.f, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("%q. buildFormatStringSliceFromString() = %v, want %v", tt.f, got, tt.want)
			}
		}
	}
}
