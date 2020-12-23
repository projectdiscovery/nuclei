package dns

import (
	"bytes"

	"github.com/miekg/dns"
)

// responseToDSLMap converts a DNS response to a map for use in DSL matching
func responseToDSLMap(msg *dns.Msg) map[string]interface{} {
	data := make(map[string]interface{}, 6)

	buffer := &bytes.Buffer{}
	for _, question := range msg.Question {
		buffer.WriteString(question.String())
	}
	data["question"] = buffer.String()
	buffer.Reset()

	for _, extra := range msg.Extra {
		buffer.WriteString(extra.String())
	}
	data["extra"] = buffer.String()
	buffer.Reset()

	for _, answer := range msg.Answer {
		buffer.WriteString(answer.String())
	}
	data["answer"] = buffer.String()
	buffer.Reset()

	for _, ns := range msg.Ns {
		buffer.WriteString(ns.String())
	}
	data["ns"] = buffer.String()
	buffer.Reset()

	data["raw"] = msg.String()
	data["status_code"] = msg.Rcode
	return data
}
