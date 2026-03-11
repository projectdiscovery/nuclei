## Bug Description

When using the time_delay analyzer, cookies set via the -H command-line flag were lost in subsequent requests when Nuclei transforms the delay time.

## Root Cause

The Cookie component's Parse method only read cookies from the CookieJar but not from the Cookie header set via -H flag. This caused cookies specified via -H "Cookie: ..." to be lost when the analyzer rebuilt requests.

## Fix

The fix modifies pkg/fuzz/component/cookie.go to:

1. Parse cookies from the Cookie header (in addition to the CookieJar) in the Parse method
2. Preserve cookies from the original request's CookieJar during Rebuild

## Testing

This fix has been tested to ensure:
- Cookies set via -H "Cookie: ..." are now properly preserved in time_delay analyzer requests
- Existing CookieJar cookies continue to work correctly

Fixes #7106
