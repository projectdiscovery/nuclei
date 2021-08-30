package replacer

import "testing"

func TestReplaceNth(t *testing.T) {
	type args struct {
		template string
		key      string
		value    string
		n        int
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 int
	}{

		{
			name: "foo",
			args: args{
				template: "path/§path§/§path§",
				key:      "path",
				value:    "foo",
				n:        1,
			},
			want:  "path/foo/path",
			want1: 2,
		},
		{
			name: "bar",
			args: args{
				template: "path/§path§/§path§",
				key:      "path",
				value:    "bar",
				n:        2,
			},
			want:  "path/path/bar",
			want1: 2,
		},
		{
			name: "none",
			args: args{
				template: "path/§path§/§path§",
				key:      "path",
				value:    "bar",
				n:        3,
			},
			want:  "path/path/path",
			want1: 2,
		},
		{
			name: "none",
			args: args{
				template: "path/§path§/§path§/§path§",
				key:      "path",
				value:    "bar",
				n:        0,
			},
			want:  "path/path/path/path",
			want1: 3,
		},
		{
			name: "foo",
			args: args{
				template: "path/{{path}}/{{path}}",
				key:      "path",
				value:    "foo",
				n:        1,
			},
			want:  "path/foo/path",
			want1: 2,
		},
		{
			name: "bar",
			args: args{
				template: "path/{{path}}/§path§",
				key:      "path",
				value:    "bar",
				n:        2,
			},
			want:  "path/path/bar",
			want1: 2,
		},
		{
			name: "none",
			args: args{
				template: "path/{{path}}/§path§",
				key:      "path",
				value:    "bar",
				n:        3,
			},
			want:  "path/path/path",
			want1: 2,
		},
		{
			name: "none",
			args: args{
				template: "path/{{path}}/§path§/§path§",
				key:      "path",
				value:    "bar",
				n:        0,
			},
			want:  "path/path/path/path",
			want1: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := ReplaceNth(tt.args.template, tt.args.key, tt.args.value, tt.args.n)
			if got != tt.want {
				t.Errorf("ReplaceNth() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ReplaceNth() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
