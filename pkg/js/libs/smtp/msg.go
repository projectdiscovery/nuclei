package smtp

import (
	"bufio"
	"bytes"
	"net/textproto"
	"strings"
)

// SMTPMessage is a simple smtp message builder
type SMTPMessage struct {
	from string
	to   []string
	sub  string
	msg  []byte
	user string
	pass string
}

// From adds the from field to the message
func (s *SMTPMessage) From(email string) *SMTPMessage {
	s.from = email
	return s
}

// To adds the to field to the message
func (s *SMTPMessage) To(email string) *SMTPMessage {
	s.to = append(s.to, email)
	return s
}

// Subject adds the subject field to the message
func (s *SMTPMessage) Subject(sub string) *SMTPMessage {
	s.sub = sub
	return s
}

// Body adds the message body to the message
func (s *SMTPMessage) Body(msg []byte) *SMTPMessage {
	s.msg = msg
	return s
}

// Auth when called authenticates using username and password before sending the message
func (s *SMTPMessage) Auth(username, password string) *SMTPMessage {
	s.user = username
	s.pass = password
	return s
}

// String returns the string representation of the message
func (s *SMTPMessage) String() string {
	var buff bytes.Buffer
	tw := textproto.NewWriter(bufio.NewWriter(&buff))
	_ = tw.PrintfLine("To: %s", strings.Join(s.to, ","))
	if s.sub != "" {
		_ = tw.PrintfLine("Subject: %s", s.sub)
	}
	_ = tw.PrintfLine("\r\n%s", s.msg)
	return buff.String()
}
