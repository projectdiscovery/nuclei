package main

import (
	"io/ioutil"
	"strconv"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
)

var dnsTestCases = map[string]testutils.TestCase{
	"dns/basic.yaml": &dnsBasic{},
}

type dnsBasic struct{}

func (h *dnsBasic) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeCNAME:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		if domain == "test.nuclei." {
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "nuclei.works.",
			})
		}
	}
	w.WriteMsg(&msg)
}

// Executes executes a test case and returns an error if occurred
func (h *dnsBasic) Execute(filePath string) error {
	var routerErr error

	srv := &dns.Server{Addr: ":" + strconv.Itoa(54), Net: "udp"}
	srv.Handler = h
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			routerErr = err
			return
		}
	}()

	err := ioutil.WriteFile("resolvers.txt", []byte("127.0.0.1:54"), 0777)
	if err != nil {
		return err
	}

	results, err := testutils.RunNucleiAndGetResults(filePath, "test.nuclei", debug, "-r", "resolvers.txt")
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	return nil
}
