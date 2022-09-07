package contextargs

import "net/http/cookiejar"

type Context struct {
	Input     string
	CookieJar *cookiejar.Jar
	Args      map[string]interface{}
}
