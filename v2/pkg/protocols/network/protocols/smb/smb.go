package smb

// ConnectWithCredentials connects to a server with credentials
func ConnectWithCredentials(host, username, password, domain string, port, timeout int, useV1 bool) (bool, error) {
	var connected bool
	var err error

	if useV1 {
		connected, err = connectWithCredentialsV1(host, username, password, domain, port, timeout)
	} else {
		connected, err = connectWithCredentials(host, username, password, domain, port, timeout)
	}
	return connected, err
}
