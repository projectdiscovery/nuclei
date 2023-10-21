package normalizer

import (
	"testing"
)

func TestDOMNormalizer_Apply(t *testing.T) {
	type args struct {
		content string
	}
	normalizer := NewDOMNormalizer(nil)

	tests := []struct {
		name    string
		d       *DOMNormalizer
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "comments-style-script",
			d:    normalizer,
			args: args{
				content: `<html><head><style>body {color: blue;}</style></head><body><h1>Hello World</h1><!-- comment --><script>alert("hi");</script></body></html>`,
			},
			want:    "<html><head></head><body><h1>Hello World</h1></body></html>",
			wantErr: false,
		},
		{
			name: "hidden input",
			d:    normalizer,
			args: args{
				content: `<html><head></head><body><input type="hidden" name="test" value="test"></body></html>`,
			},
			want:    "<html><head></head><body></body></html>",
			wantErr: false,
		},
		// write tests for other cases
		{
			name: "csrf",
			d:    normalizer,
			args: args{
				content: `<html><head></head><body><input name="csrf" value="test"></body></html>`,
			},
			want:    "<html><head></head><body></body></html>",
			wantErr: false,
		},
		{
			name: "class-id-data-attributes",
			d:    normalizer,
			args: args{
				content: `<html><head></head><body><div class="test" id="test" data-test="test"></div></body></html>`,
			},
			want: "<html><head></head><body></body></html>",
		},
		{
			name: "inline-style",
			d:    normalizer,
			args: args{
				content: `<html><head></head><body><div style="color: blue;"></div></body></html>`,
			},
			want: "<html><head></head><body></body></html>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := normalizer
			got, err := d.Apply(tt.args.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("DOMNormalizer.Apply() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DOMNormalizer.Apply() = %v, want %v", got, tt.want)
			}
		})
	}
}
