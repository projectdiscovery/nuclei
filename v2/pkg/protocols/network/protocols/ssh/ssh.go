package ssh

import (
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// ConnectWithCredentials connects to a server with credentials
//
// password also supports private ssh keys which will
// be parsed for further authenticated.
func ConnectWithCredentials(host, username, password string, port, timeout int) (bool, error) {
	auth, err := genAuthMethod(password)
	if err != nil {
		return false, errors.Wrap(err, "could not create ssh auth")
	}
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            auth,
		Timeout:         time.Duration(timeout) * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-2.0-Go-Nuclei-SSH",
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		return false, errors.Wrap(err, "could not dial ssh")
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return false, errors.Wrap(err, "could not create session")
	}
	data, err := session.Output("echo nuclei")
	if err != nil {
		return false, errors.Wrap(err, "could not execute ssh")
	}
	_ = session.Close()

	if !strings.Contains(string(data), "nuclei") {
		return false, nil
	}
	return true, nil
}

func challengeReponder(password string) ssh.KeyboardInteractiveChallenge {
	return func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = password
		}
		return answers, nil
	}
}

func genAuthMethod(password string) ([]ssh.AuthMethod, error) {
	if strings.HasPrefix(password, "-----BEGIN") {
		signer, err := ssh.ParsePrivateKey([]byte(password))
		if err != nil {
			return []ssh.AuthMethod{}, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	return []ssh.AuthMethod{
		ssh.Password(password),
		ssh.KeyboardInteractive(challengeReponder(password)),
	}, nil
}
