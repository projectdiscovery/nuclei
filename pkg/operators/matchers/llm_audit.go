package matchers

import (
	"crypto/sha256"
	"encoding/hex"
)

// LLMAudit records what the model was asked and what it answered.
//
// An llm verdict is not reproducible the way a regex match is: the same
// response can classify differently under a different model or a rewritten
// prompt. Carrying the model, a hash of the prompt, and the verdict with its
// confidence is what lets someone triage a finding later, and tell two findings
// apart when the template has changed underneath them.
type LLMAudit struct {
	// Model is the model that returned the verdict.
	Model string `json:"model,omitempty"`
	// PromptHash identifies the prompt without reproducing it. The prompt
	// embeds part of the response, which can carry target data, so only the
	// hash travels into output.
	PromptHash string `json:"prompt-hash,omitempty"`
	// Verdict is the answer the model gave, from the matcher's allowed set.
	Verdict string `json:"verdict,omitempty"`
	// Confidence is the model's confidence in that verdict, 0 to 1.
	Confidence float64 `json:"confidence,omitempty"`
}

// modelNamer is implemented by clients that can name the model they call, so
// the audit can record it without the matchers package importing a provider.
type modelNamer interface {
	Model() string
}

// hashPrompt returns a short, stable identifier for a prompt.
func hashPrompt(prompt string) string {
	sum := sha256.Sum256([]byte(prompt))

	return hex.EncodeToString(sum[:])[:16]
}
