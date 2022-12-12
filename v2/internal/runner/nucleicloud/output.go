package nucleicloud

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func DisplayScanListInJson(output ListScanOutput) {
	bytes, _ := json.Marshal(output)
	os.Stdout.Write(bytes)
}

func DisplayScanList(output ListScanOutput) {
	gologger.Silent().Msgf("%s [%s] [STATUS: %s] [MATCHED: %d] [TARGETS: %d] [TEMPLATES: %d] [DURATION: %s]\n", output.Timestamp, output.ScanID, strings.ToUpper(output.ScanStatus), output.ScanResult, output.Target, output.Template, output.ScanTime)
}
