package sandbox

import "github.com/projectdiscovery/utils/errkit"

var ErrNoAllowedRoots = errkit.New("no allowed filesystem roots configured for sandbox")
