package templates

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Capability identifies an opt-in capability a template may require.
type Capability string

const (
	// CapabilityHeadless requires the -headless flag.
	CapabilityHeadless Capability = "headless"
	// CapabilityCode requires the -code flag.
	CapabilityCode Capability = "code"
	// CapabilityDAST requires the -dast flag.
	CapabilityDAST Capability = "dast"
	// CapabilitySelfContained requires the -enable-self-contained flag.
	CapabilitySelfContained Capability = "self-contained"
	// CapabilityGlobalMatchers requires the -enable-global-matchers flag.
	CapabilityGlobalMatchers Capability = "global-matchers"
	// CapabilityFile requires the -file flag.
	CapabilityFile Capability = "file"
)

type capabilityDefinition struct {
	capability   Capability
	stat         string
	flag         string
	templateKind string
	loadBlocking bool
	enabled      func(*types.Options) bool
	required     func(*Template) bool
}

var capabilityDefinitions = []capabilityDefinition{
	{
		capability:   CapabilityHeadless,
		stat:         ExcludedHeadlessTemplateStats,
		flag:         "-headless",
		templateKind: "headless",
		loadBlocking: true,
		enabled: func(options *types.Options) bool {
			return options.Headless
		},
		required: func(template *Template) bool {
			return template.HasHeadlessRequest()
		},
	},
	{
		capability:   CapabilityCode,
		stat:         ExcludedCodeTemplateStats,
		flag:         "-code",
		templateKind: "code protocol",
		loadBlocking: true,
		enabled: func(options *types.Options) bool {
			return options.EnableCodeTemplates
		},
		required: func(template *Template) bool {
			return template.HasCodeRequest()
		},
	},
	{
		capability:   CapabilityDAST,
		stat:         ExcludedDASTTemplateStats,
		flag:         "-dast",
		templateKind: "DAST",
		loadBlocking: true,
		enabled: func(options *types.Options) bool {
			return options.DAST
		},
		required: func(template *Template) bool {
			return template.IsFuzzableRequest()
		},
	},
	{
		capability:   CapabilitySelfContained,
		stat:         ExcludedSelfContainedTemplateStats,
		flag:         "-enable-self-contained",
		templateKind: "self-contained",
		loadBlocking: true,
		enabled: func(options *types.Options) bool {
			return options.EnableSelfContainedTemplates
		},
		required: func(template *Template) bool {
			return template.requiresSelfContained()
		},
	},
	{
		capability:   CapabilityGlobalMatchers,
		stat:         ExcludedGlobalMatchersTemplateStats,
		flag:         "-enable-global-matchers",
		templateKind: "global matchers",
		loadBlocking: false,
		enabled: func(options *types.Options) bool {
			return options.EnableGlobalMatchersTemplates
		},
		required: func(template *Template) bool {
			return template.requiresGlobalMatchers()
		},
	},
	{
		capability:   CapabilityFile,
		stat:         ExcludedFileTemplateStats,
		flag:         "-file",
		templateKind: "file",
		loadBlocking: true,
		enabled: func(options *types.Options) bool {
			return options.EnableFileTemplates
		},
		required: func(template *Template) bool {
			return template.HasFileRequest()
		},
	},
}

// AllCapabilities returns all template execution capabilities in evaluation order.
func AllCapabilities() []Capability {
	capabilities := make([]Capability, 0, len(capabilityDefinitions))
	for _, definition := range capabilityDefinitions {
		capabilities = append(capabilities, definition.capability)
	}

	return capabilities
}

// Stat returns the stats key for a missing capability.
func (capability Capability) Stat() string {
	definition, _ := capability.definition()

	return definition.stat
}

// Flag returns the CLI flag enabling the capability.
func (capability Capability) Flag() string {
	definition, _ := capability.definition()

	return definition.flag
}

// TemplateKind returns the template kind label used in missing-flag messages.
func (capability Capability) TemplateKind() string {
	definition, found := capability.definition()
	if !found {
		return string(capability)
	}

	return definition.templateKind
}

func (capability Capability) definition() (capabilityDefinition, bool) {
	for _, definition := range capabilityDefinitions {
		if definition.capability == capability {
			return definition, true
		}
	}

	return capabilityDefinition{}, false
}

// MissingFlagMessage returns a per-template message for a missing capability.
func (capability Capability) MissingFlagMessage(templatePath string) string {
	return fmt.Sprintf("%s flag is required for %s template %q.", capability.Flag(), capability.TemplateKind(), templatePath)
}

// CapabilitySet represents enabled template execution capabilities.
type CapabilitySet map[Capability]bool

// CapabilitiesFromOptions returns the template capabilities enabled by options.
func CapabilitiesFromOptions(options *types.Options) CapabilitySet {
	capabilities := make(CapabilitySet, len(capabilityDefinitions))
	for _, definition := range capabilityDefinitions {
		capabilities[definition.capability] = definition.enabled(options)
	}

	return capabilities
}

// Has returns true when a capability is enabled.
func (caps CapabilitySet) Has(capability Capability) bool {
	return caps[capability]
}

// RequiredCapabilities returns the opt-in capabilities required by the template.
func (template *Template) RequiredCapabilities() []Capability {
	var required []Capability

	for _, definition := range capabilityDefinitions {
		if definition.required(template) {
			required = append(required, definition.capability)
		}
	}

	return required
}

func (template *Template) requiresSelfContained() bool {
	if template.SelfContained {
		return true
	}

	for _, request := range template.RequestsHTTP {
		if request != nil && request.SelfContained {
			return true
		}
	}
	for _, request := range template.RequestsNetwork {
		if request != nil && request.SelfContained {
			return true
		}
	}
	for _, request := range template.RequestsHeadless {
		if request != nil && request.SelfContained {
			return true
		}
	}

	return false
}

func (template *Template) requiresGlobalMatchers() bool {
	for _, request := range template.RequestsHTTP {
		if request != nil && request.GlobalMatchers {
			return true
		}
	}

	return false
}

// MissingCapabilities returns all disabled capabilities required by the template.
func (template *Template) MissingCapabilities(caps CapabilitySet) []Capability {
	return template.missingCapabilities(caps, false)
}

// MissingLoadCapabilities returns disabled capabilities that prevent a template
// from being loaded into the execution store.
func (template *Template) MissingLoadCapabilities(caps CapabilitySet) []Capability {
	return template.missingCapabilities(caps, true)
}

func (template *Template) missingCapabilities(caps CapabilitySet, loadOnly bool) []Capability {
	var missing []Capability

	for _, definition := range capabilityDefinitions {
		if loadOnly && !definition.loadBlocking {
			continue
		}
		if definition.required(template) && !caps.Has(definition.capability) {
			missing = append(missing, definition.capability)
		}
	}

	return missing
}
