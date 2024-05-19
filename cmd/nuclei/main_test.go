package main

import (
	"testing"

	"github.com/projectdiscovery/goflags"
)

func TestNuclei(t *testing.T) {
	command := `-u https://scanme.sh -stats -pt dns`
	run(goflags.GetArgsFromString(command)...)
}
