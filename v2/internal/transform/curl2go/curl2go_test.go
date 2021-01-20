package curl2go

import (
	"fmt"
	"testing"
	"time"
)

func TestCurlToGo(t *testing.T) {
	now := time.Now()
	req, err := Parse(`curl -i -s -k -X $'POST' \
    -H $'Host: www.w3schools.com' -H $'Connection: close' -H $'Content-Length: 230' -H $'Cache-Control: max-age=0' -H $'Upgrade-Insecure-Requests: 1' -H $'Origin: https://www.w3schools.com' -H $'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryV2BMkEBV9QZA72mW' -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' -H $'Sec-Fetch-Site: same-origin' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-User: ?1' -H $'Sec-Fetch-Dest: iframe' -H $'Referer: https://www.w3schools.com/TAgs/tryit.asp?filename=tryhtml_form_enctype' -H $'Accept-Encoding: gzip, deflate' -H $'Accept-Language: en-US,en;q=0.9,hi;q=0.8' \
    -b $'G_ENABLED_IDPS=google' \
    --data-binary $'------WebKitFormBoundaryV2BMkEBV9QZA72mW\x0d\x0aContent-Disposition: form-data; name=\"fname\"\x0d\x0a\x0d\x0a1\x0d\x0a------WebKitFormBoundaryV2BMkEBV9QZA72mW\x0d\x0aContent-Disposition: form-data; name=\"lname\"\x0d\x0a\x0d\x0a2\x0d\x0a------WebKitFormBoundaryV2BMkEBV9QZA72mW--\x0d\x0a' \
    $'https://www.w3schools.com/action_page_binary.asp'`)
	fmt.Printf("%v %v\n", req, err)
	fmt.Printf("Took :%v\n", time.Since(now))
}
