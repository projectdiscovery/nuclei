package utils_test

import (
	"fmt"
	"path"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/utils"
)

func TestURLJoin(t *testing.T) {
	fmt.Println(path.Join("/wp-content", "/wp-content/admin.php"))
	testcases := []struct {
		URL1         string
		URL2         string
		ExpectedJoin string
	}{
		{"/test/", "", "/test/"},
		{"/test", "/", "/test/"},
		{"/test", "?param=true", "/test?param=true"},
		{"/test/", "/", "/test/"},
	}
	for _, v := range testcases {
		res := utils.JoinURLPath(v.URL1, v.URL2)
		if res != v.ExpectedJoin {
			t.Errorf("failed to join urls expected %v but got %v", v.ExpectedJoin, res)
		}
	}
}
