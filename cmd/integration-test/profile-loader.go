package main

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var profileLoaderTestcases = []TestCaseInfo{
	{Path: "profile-loader/load-with-filename", TestCase: &profileLoaderByRelFile{}},
	{Path: "profile-loader/load-with-id", TestCase: &profileLoaderById{}},
	{Path: "profile-loader/basic.yml", TestCase: &customProfileLoader{}},
}

type profileLoaderByRelFile struct{}

func (h *profileLoaderByRelFile) Execute(testName string) error {
	results, err := testutils.RunNucleiWithArgsAndGetResults(false, "-tl", "-tp", "cloud.yml")
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to load template with id")
	}
	if len(results) <= 10 {
		return fmt.Errorf("incorrect result: expected more results than %d, got %v", 10, len(results))
	}
	return nil
}

type profileLoaderById struct{}

func (h *profileLoaderById) Execute(testName string) error {
	results, err := testutils.RunNucleiWithArgsAndGetResults(false, "-tl", "-tp", "cloud")
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to load template with id")
	}
	if len(results) <= 10 {
		return fmt.Errorf("incorrect result: expected more results than %d, got %v", 10, len(results))
	}
	return nil
}

// this profile with load kevs
type customProfileLoader struct{}

func (h *customProfileLoader) Execute(filepath string) error {
	results, err := testutils.RunNucleiWithArgsAndGetResults(false, "-tl", "-tp", filepath)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to load template with id")
	}
	if len(results) < 1 {
		return fmt.Errorf("incorrect result: expected more results than %d, got %v", 1, len(results))
	}
	return nil
}
