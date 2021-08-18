package replacer

import (
	"testing"
)

func TestReplaceNth(t *testing.T) {
	type args struct {
		template string
		key      string
		value    string
		n        int
	}
	tests := []struct {
		name string
		args args
		want string
	}{

		{
			name: "foo",
			args: args{
				template: "path/§path§/§path§",
				key:      "path",
				value:    "foo",
				n:        1,
			},
			want: "path/foo/path",
		},
		{
			name: "bar",
			args: args{
				template: "path/§path§/§path§",
				key:      "path",
				value:    "bar",
				n:        2,
			},
			want: "path/path/bar",
		},
		{
			name: "none",
			args: args{
				template: "path/§path§/§path§",
				key:      "path",
				value:    "bar",
				n:        3,
			},
			want: "path/path/path",
		},
		{
			name: "none",
			args: args{
				template: "path/§path§/§path§",
				key:      "path",
				value:    "bar",
				n:        0,
			},
			want: "path/path/path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReplaceNth(tt.args.template, tt.args.key, tt.args.value, tt.args.n); got != tt.want {
				t.Errorf("ReplaceNth() = %v, want %v", got, tt.want)
			}
		})
	}
}