package kerberos

import (
	"fmt"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
)

// Updated Package definations and structure
type Client struct {
	nj *utils.NucleiJS // helper functions/bindings
}

// Constructor for KerberosClient
// creates client object and can be created using new
// var client = new kerberos.Client(domain,controller);
func NewKerberosClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	// setup nucleijs utils
	c := &Client{nj: utils.NewNucleiJS(runtime)}
	c.nj.ObjectSig = "Client(domain, controller)" // will be included in error messages

	// get arguments (type assertion is efficient than reflection)
	// when accepting type as input like net.Conn we can use utils.GetArg
	domain, _ := c.nj.GetArg(call.Arguments, 0).(string)
	controller, _ := c.nj.GetArg(call.Arguments, 1).(string)

	// validate arguments
	c.nj.Require(domain != "", "domain cannot be empty")
	c.nj.Require(controller != "", "controller cannot be empty")

	// Link Constructor to Client and return
	return utils.LinkConstructor(call, runtime, c)
}

// EnumerateUserResponse is the response from EnumerateUsers
func (c *Client) EnumerateUser(username string) (EnumerateUserResponse, error) {
	return EnumerateUserResponse{}, nil
}

type ServiceOptions struct {
	Username string
	Password string
	Target   string
	SPN      string
}

func (c *Client) GetServiceTicket(sv ServiceOptions) (TGS, error) {
	fmt.Printf("get service ticket %v\n", sv)
	return TGS{}, nil
}

// prefer using string or hex over byte array in javascript modules
func (c *Client) Send(data string) (string, error) {
	return "", nil
}
