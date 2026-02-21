package analyzers

import (
	"strings"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
)

type XSSContextAnalyzer struct{}

func (a *XSSContextAnalyzer) Name() string {
	return "xss_context"
}

func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data
}

func (a *XSSContextAnalyzer) Analyze(options *fuzz.AnalyzeOptions) (bool, string, error) {
	// تصحيح: بنفحص الـ Response اللي جاي من السيرفر مش الـ Request
	// ده بيصلح ملاحظة Coderabbit (image_5baa41)
	if options.Resp == nil || options.Resp.Body == "" {
		return false, "", nil
	}

	body := strings.ToLower(options.Resp.Body)
	
	// فحص أكثر دقة للسياق (Context)
	if strings.Contains(body, "<script>") {
		return true, "reflected_in_script_tag", nil
	}
	
	if strings.Contains(body, "onmouseover=") || strings.Contains(body, "onerror=") {
		return true, "reflected_in_attribute_event", nil
	}

	return false, "", nil
}

func init() {
	fuzz.RegisterAnalyzer("xss_context", &XSSContextAnalyzer{})
}
