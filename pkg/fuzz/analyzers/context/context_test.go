package context

import (
	"testing"
)

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		payload   string
		wantVuln  bool
		wantCtx   ContextType
	}{
		{
			name:     "Basic Body Reflection",
			body:     "<div><h1>payload</h1></div>",
			payload:  "<h1>",
			wantVuln: true,
			wantCtx:  ContextHTMLBody,
		},
		{
			name:     "Escaped Body",
			body:     "<div>&lt;h1&gt;payload&lt;/h1&gt;</div>",
			payload:  "<h1>",
			wantVuln: false,
            // Since fast path returns ContextUnknown if not found
			wantCtx: ContextUnknown,
		},
		{
			name:     "Attribute Breakout",
			body:     "<input value=\"\">\">",
			payload:  "\">",
			wantVuln: true,
            // Breaking out often results in being in HTMLBody or just a mess, current logic says HTMLBody
			wantCtx:  ContextHTMLBody,
		},
		{
			name:     "Attribute Safe",
			body:     "<input value=\"hello\">",
			payload:  "hello",
			wantVuln: false,
			wantCtx:  ContextAttributeValueDoubleQuote,
		},
		{
			name:     "Script Execution",
			body:     "<script>var x = 1; alert(1)</script>",
			payload:  "1; alert(1)",
			wantVuln: true,
			wantCtx:  ContextScript,
		},
		{
			name:     "Script String Safe",
			body:     "<script>var x = \"alert(1)\"</script>",
			payload:  "alert(1)",
			wantVuln: false,
			wantCtx:  ContextScript,
		},
		{
			name:     "Script String Breakout",
			body:     "<script>var x = \"\"; alert(1); //\"</script>",
			payload:  "\"; alert(1); //",
			wantVuln: true,
			wantCtx:  ContextScript,
		},
		{
			name:     "Comment Safe",
			body:     "<!-- alert(1) -->",
			payload:  "alert(1)",
			wantVuln: false,
			wantCtx:  ContextComment,
		},
		{
			name:     "Comment Breakout",
			body:     "<!-- --> <script>alert(1)</script> -->",
			payload:  "--> <script>alert(1)</script>",
			wantVuln: true,
            // It breaks out and executes as script
			wantCtx:  ContextScript,
		},
		{
			name:     "Textarea Safe",
			body:     "<textarea><script></textarea>",
			payload:  "<script>",
			wantVuln: false,
			wantCtx:  ContextRCDATA,
		},
		{
			name:     "Textarea Breakout",
			body:     "<textarea></textarea><script></textarea>",
			payload:  "</textarea><script>",
			wantVuln: true,
			wantCtx:  ContextRCDATA,
		},
        {
            name:     "Attribute Name Injection",
            body:     "<div onmouseover=\"x\"></div>",
            payload:  "onmouseover",
            wantVuln: true,
            wantCtx:  ContextAttributeName,
        },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Analyze([]byte(tt.body), tt.payload)
			if got.Vulnerable != tt.wantVuln {
				t.Errorf("Analyze() vulnerable = %v, want %v (Reason: %s, Context: %s)", got.Vulnerable, tt.wantVuln, got.Reason, got.Context.String())
			}
			if got.Context != tt.wantCtx {
				t.Errorf("Analyze() context = %v, want %v", got.Context, tt.wantCtx)
			}
		})
	}
}
