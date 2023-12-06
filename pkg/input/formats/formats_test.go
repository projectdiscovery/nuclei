package formats

import "testing"

func TestParseRawRequest(t *testing.T) {
	raw := `POST /login HTTP/1.1
Host: ginandjuice.shop
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,hi;q=0.8
Cache-Control: max-age=0
Connection: close
Content-Length: 70
Content-Type: application/x-www-form-urlencoded
Cookie: session=iIDKgm31y9H8OmNfR88b2tf4F0aVE1o9; TrackingId=eyJ0eXBlIjoiY2xhc3MiLCJ2YWx1ZSI6InkyRTQ5UzdBNFdiWUVDZEYifQ==; AWSALB=N4X+LM0iOhNJhryXJwMLhlHdoTlFQLArV2UlGimRQ3HkQcKZ3gkIlldJJsoAsYDJJktefRQZp41WDwPLsQ2sH9w999kXyruPLCZbY5xbMOuxca/pLrWMiByGzuFx; AWSALBCORS=N4X+LM0iOhNJhryXJwMLhlHdoTlFQLArV2UlGimRQ3HkQcKZ3gkIlldJJsoAsYDJJktefRQZp41WDwPLsQ2sH9w999kXyruPLCZbY5xbMOuxca/pLrWMiByGzuFx
Origin: https://ginandjuice.shop
Referer: https://ginandjuice.shop/login
Sec-Ch-Ua: "Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36

	`

	body := `csrf=5imRvKFyxcz3XTpEKjNd3yJb2vKnTvjB&username=carlos&password=hunter2`

	rawRequest, err := ParseRawRequest(raw, body, "https://ginandjuice.shop/login")
	if err != nil {
		t.Fatal(err)
	}

	if rawRequest.URL != "https://ginandjuice.shop/login" {
		t.Fatalf("invalid url: %s", rawRequest.URL)
	}
	if rawRequest.Method != "POST" {
		t.Fatalf("invalid method: %s", rawRequest.Method)
	}
	if rawRequest.Body != body {
		t.Fatalf("invalid body: %s", rawRequest.Body)
	}
	if rawRequest.Raw != raw {
		t.Fatalf("invalid raw: %s", rawRequest.Raw)
	}
}
