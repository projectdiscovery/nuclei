package utils

import (
	"time"
)

// Sleep pauses execution for the specified number of milliseconds
// @example
// ```javascript
// const utils = require('nuclei/utils');
// utils.Sleep(1000); // sleep for 1 second
// ```
func (u *Utils) Sleep(milliseconds int) {
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)
}

// UnixTimestamp returns the current Unix timestamp in seconds
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const ts = utils.UnixTimestamp();
// ```
func (u *Utils) UnixTimestamp() int64 {
	return time.Now().Unix()
}

// UnixTimestampMilli returns the current Unix timestamp in milliseconds
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const ts = utils.UnixTimestampMilli();
// ```
func (u *Utils) UnixTimestampMilli() int64 {
	return time.Now().UnixMilli()
}

// UnixTimestampNano returns the current Unix timestamp in nanoseconds
// @example
// ```javascript
// const utils = require('nuclei/utils');
// const ts = utils.UnixTimestampNano();
// ```
func (u *Utils) UnixTimestampNano() int64 {
	return time.Now().UnixNano()
}
