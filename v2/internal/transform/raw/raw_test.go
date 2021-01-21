package raw

import (
	"fmt"
	"testing"
	"time"
)

func TestRawRequest(t *testing.T) {
	now := time.Now()
	req, err := Parse(`POST /reflected/parameter/form HTTP/1.1
	Host: public-firing-range.appspot.com
	Connection: close
	Content-Length: 6
	Cache-Control: max-age=0
	Upgrade-Insecure-Requests: 1
	Origin: https://public-firing-range.appspot.com
	Content-Type: application/x-www-form-urlencoded
	User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
	Sec-Fetch-Site: same-origin
	Sec-Fetch-Mode: navigate
	Sec-Fetch-User: ?1
	Sec-Fetch-Dest: document
	Referer: https://public-firing-range.appspot.com/reflected/parameter/form
	Accept-Encoding: gzip, deflate
	Accept-Language: en-US,en;q=0.9,hi;q=0.8
	
	q=1234`, "http://test.com")
	fmt.Printf("%v %v\n", req, err)
	fmt.Printf("Took :%v\n", time.Since(now))
}
