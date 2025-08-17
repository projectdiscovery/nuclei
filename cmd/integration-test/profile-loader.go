package main

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/utils/errkit"
)

var profileLoaderTestcases = []TestCaseInfo{
	{Path: "profile-loader/load-with-filename", TestCase: &profileLoaderByRelFile{}},
	{Path: "profile-loader/load-with-id", TestCase: &profileLoaderById{}},
	{Path: "profile-loader/basic.yml", TestCase: &customProfileLoader{}},
}

type profileLoaderByRelFile struct{}

func (h *profileLoaderByRelFile) Execute(testName string) error {
	results, err := testutils.RunNucleiWithArgsAndGetResults(debug, "-tl", "-tp", "cloud.yml")
	if err != nil {
		return errkit.Append(errkit.New("failed to load template with id"), err)
	}
	if len(results) <= 10 {
		return fmt.Errorf("incorrect result: expected more results than %d, got %v", 10, len(results))
	}
	return nil
}

type profileLoaderById struct{}

func (h *profileLoaderById) Execute(testName string) error {
	results, err := testutils.RunNucleiWithArgsAndGetResults(debug, "-tl", "-tp", "cloud")
	if err != nil {
		return errkit.Append(errkit.New("failed to load template with id"), err)
	}
	if len(results) <= 10 {
		return fmt.Errorf("incorrect result: expected more results than %d, got %v", 10, len(results))
	}
	return nil
}

// this profile with load kevs
type customProfileLoader struct{}

func (h *customProfileLoader) Execute(filepath string) error {
	results, err := testutils.RunNucleiWithArgsAndGetResults(debug, "-tl", "-tp", filepath)
	if err != nil {
		return errkit.Append(errkit.New("failed to load template with id"), err)
	}
	if len(results) < 1 {
		return fmt.Errorf("incorrect result: expected more results than %d, got %v", 1, len(results))
	}
	return nil
}
