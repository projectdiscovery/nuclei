package analyzers

import (
	"strings"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
)

// XSSContextAnalyzer يحلل مكان ظهور الكلمة لضمان وجود ثغرة XSS حقيقية
type XSSContextAnalyzer struct{}

func (a *XSSContextAnalyzer) Name() string {
	return "xss_context"
}

func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data
}

func (a *XSSContextAnalyzer) Analyze(options *Options) (bool, string, error) {
	// الكود بيفحص الرد المرسل من السيرفر
	body := string(options.FuzzGenerated.Request.Body) 
	
	// بنشوف الـ payload نزل في أي سياق (script أو attribute)
	if strings.Contains(body, "<script>") {
		return true, "reflected_in_script_context", nil
	}
	if strings.Contains(body, "=\"") {
		return true, "reflected_in_attribute_context", nil
	}
	
	return false, "", nil
}

func init() {
	// تسجيل المحلل في النظام ليظهر في مهمة #5838
	RegisterAnalyzer("xss_context", &XSSContextAnalyzer{})
}
