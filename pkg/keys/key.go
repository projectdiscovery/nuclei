// keys package contains the public key for verifying digital signature of templates
package keys

import _ "embed"

//go:embed nuclei.crt
var NucleiCert []byte // public key for verifying digital signature of templates
