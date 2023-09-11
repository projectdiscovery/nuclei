package structs

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
	net "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libnet"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/global/gotypes/buffer"
)

func TestStructsJSPack(t *testing.T) {
	registry := new(require.Registry)
	runtime := goja.New()
	registry.Enable(runtime)
	console.Enable(runtime)
	_ = runtime.Set("print", fmt.Println)
	bufferModule := &buffer.Module{}
	bufferModule.Enable(runtime)
	module := &Module{}
	module.Enable(runtime)
	net.Enable(runtime)

	cases := []struct {
		f    string
		want []byte
		e    bool
	}{
		{
			"structs.pack('??', [true, false]);", []byte{1, 0}, false,
		},
		{
			"structs.pack('hhh', [0, 5, -5]);", []byte{0, 0, 5, 0, 251, 255}, false,
		},
		{
			"structs.pack('1s2s10s', ['a', 'bb', '1234567890']);", []byte{97, 98, 98, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48}, false,
		},
		// we need a proper and valid test server to test this
		// {
		// 	`let header = bytes.Buffer();

		// 	// Create the SMB packet first
		// 	header.append(structs.pack("B", 254));  // magic
		// 	header.append("SMB");
		// 	header.append(structs.pack("H", 64)); // header size
		// 	header.append(structs.pack("H", 0)); // credit charge
		// 	header.append(structs.pack("H", 0)); // channel sequence
		// 	header.append(structs.pack("H", 0)); // reserved
		// 	header.append(structs.pack("H", 0)); // negotiate protocol command
		// 	header.append(structs.pack("H", 31)); // credits requested
		// 	header.append(structs.pack("I", 0)); // flags
		// 	header.append(structs.pack("I", 0)); // chain offset
		// 	header.append(structs.pack("Q", 0)); // message id
		// 	header.append(structs.pack("I", 0)); // process id
		// 	header.append(structs.pack("I", 0)); // tree id
		// 	header.append(structs.pack("Q", 0)); // session id
		// 	header.append(structs.pack("QQ", [0, 0]));	// signature

		// 	// Create negotiation packet
		// 	let negotiation = bytes.Buffer();
		// 	negotiation.append(structs.pack("H", 0x24)); // struct size
		// 	negotiation.append(structs.pack("H", 8)); // amount of dialects
		// 	negotiation.append(structs.pack("H", 1)); // enable signing
		// 	negotiation.append(structs.pack("H", 0)); // reserved
		// 	negotiation.append(structs.pack("I", 0x7f)); // capabilities
		// 	negotiation.append(structs.pack("QQ", [(0 >> 64) & 0xffffffffffffffff, 0 & 0xffffffffffffffff])); // client guid
		// 	negotiation.append(structs.pack("I", 0x78)); // negotiation offset
		// 	negotiation.append(structs.pack("H", 2)); // negotiation context count
		// 	negotiation.append(structs.pack("H", 0)); // reserved
		// 	negotiation.append(structs.pack("H", 0x0202)); // smb 2.0.2 dialect
		// 	negotiation.append(structs.pack("H", 0x0210)); // smb 2.1.0 dialect
		// 	negotiation.append(structs.pack("H", 0x0222)); // smb 2.2.2 dialect
		// 	negotiation.append(structs.pack("H", 0x0224)); // smb 2.2.4 dialect
		// 	negotiation.append(structs.pack("H", 0x0300)); // smb 3.0.0 dialect
		// 	negotiation.append(structs.pack("H", 0x0302)); // smb 3.0.2 dialect
		// 	negotiation.append(structs.pack("H", 0x0310)); // smb 3.1.0 dialect
		// 	negotiation.append(structs.pack("H", 0x0311)); // smb 3.1.1 dialect
		// 	negotiation.append(structs.pack("I", 0)); // padding
		// 	negotiation.append(structs.pack("H", 1)); // negotiation context type
		// 	negotiation.append(structs.pack("H", 38)); // negotiation data length
		// 	negotiation.append(structs.pack("I", 0)); // reserved
		// 	negotiation.append(structs.pack("H", 1)); // negotiation hash algorithm count
		// 	negotiation.append(structs.pack("H", 32)); // negotiation salt length
		// 	negotiation.append(structs.pack("H", 1)); // negotiation hash algorithm SHA512
		// 	negotiation.append(structs.pack("H", 1)); // negotiation hash algorithm SHA512
		// 	negotiation.append(structs.pack("QQ", [(0 >> 64) & 0xffffffffffffffff, 0 & 0xffffffffffffffff])); // salt part 1
		// 	negotiation.append(structs.pack("QQ", [(0 >> 64) & 0xffffffffffffffff, 0 & 0xffffffffffffffff])); // salt part 2
		// 	negotiation.append(structs.pack("H", 3)); // unknown??
		// 	negotiation.append(structs.pack("H", 10)); // data length unknown??
		// 	negotiation.append(structs.pack("I", 0)); // reserved unknown??
		// 	negotiation.append("\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"); // unknown

		// 	let packet = bytes.Buffer();
		// 	packet.append(header.bytes());
		// 	packet.append(negotiation.bytes());

		// 	let netbios = bytes.Buffer();
		// 	netbios.append(structs.pack("H", 0)); // NetBIOS sessions message (should be 1 byte but whatever)
		// 	netbios.append(structs.pack("B", 0)); // just a pad to make it 3 bytes
		// 	netbios.append(structs.pack("B", packet.len())); // NetBIOS length (should be 3 bytes but whatever, as long as the packet isn't 0xff+ bytes)

		// 	let final = bytes.Buffer();
		// 	final.append(netbios.bytes());
		// 	final.append(packet.bytes());

		// 	console.log("Netbios", netbios.hex(), netbios.len());
		// 	console.log("Header", header.hex(), header.len());
		// 	console.log("Negotation", negotiation.hex(), negotiation.len());
		// 	console.log("Packet", final.hex(), final.len());

		// 	console.log("Dumping hexdump of final packet");
		// 	print(final.hexdump());

		// 	let c = require("nuclei/net");
		// 	let conn = c.Open("tcp", "118.68.186.114:445");
		// 	conn.Send(final.bytes(), 0);
		// 	let bytesRecv = conn.Recv(0, 4);
		// 	console.log("recv Bytes", bytesRecv);
		// 	let size = structs.unpack("I", bytesRecv)[0];
		// 	console.log("Size", size);
		// 	let data = conn.Recv(0, size);
		// 	console.log("Data", data);

		// 	// TODO: Add hexdump helpers

		// 	version = structs.unpack("H", data.slice(68,70))[0]
		// 	context = structs.unpack("H", data.slice(70,72))[0]

		// 	console.log("Version", version);
		// 	console.log("Context", context);

		// 	if (version != 0x0311){
		// 		console.log("SMB version", version, "was found which is not vulnerable!");
		// 	} else if (context != 2) {
		// 		console.log("Server answered with context", context, "which indicates that the target may not have SMB compression enabled and is therefore not vulnerable!");
		// 	} else {
		// 		console.log("SMB version", version, "with context", context, "was found which indicates SMBv3.1.1 is being used and SMB compression is enabled, therefore being vulnerable to CVE-2020-0796!");
		// 	}
		// 	conn.Close();
		// 	`,
		// 	[]byte{},
		// 	false,
		// },
	}
	for _, tt := range cases {
		value, err := runtime.RunString(tt.f)
		if err != nil {
			t.Errorf("StructsJSPack() error f = %v = %v", tt.f, err)
			continue
		}
		var got []byte
		switch v := value.Export().(type) {
		case []byte:
			got = v
		case string:
			fmt.Printf("Got %+v\n", v)
			got = []byte(v)
		}
		hexStr := hex.EncodeToString(got)
		fmt.Printf("%v\n", hexStr)
		if len(got) != len(tt.want) {
			t.Errorf("StructsJSPack() = %v, want %v", got, tt.want)
		}
		fmt.Printf("f=%v want=%v got=%v\n", tt.f, tt.want, got)
		if got[0] != tt.want[0] {
			t.Errorf("StructsJSPack() = %v, want %v", got, tt.want)
		}

	}
}

func TestStructsPack(t *testing.T) {
	cases := []struct {
		f    string
		a    []interface{}
		want []byte
		e    bool
	}{
		{"??", []interface{}{true, false}, []byte{1, 0}, false},
		{"hhh", []interface{}{0, 5, -5},
			[]byte{0, 0, 5, 0, 251, 255}, false},
		{"HHH", []interface{}{0, 5, 2300}, []byte{0, 0, 5, 0, 252, 8}, false},
		{"iii", []interface{}{0, 5, -5},
			[]byte{0, 0, 0, 0, 5, 0, 0, 0, 251, 255, 255, 255}, false},
		{"III", []interface{}{0, 5, 2300},
			[]byte{0, 0, 0, 0, 5, 0, 0, 0, 252, 8, 0, 0}, false},
		{"fff", []interface{}{float32(0.0), float32(5.3), float32(-5.3)},
			[]byte{0, 0, 0, 0, 154, 153, 169, 64, 154, 153, 169, 192}, false},
		{"ddd", []interface{}{0.0, 5.3, -5.3},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 51, 51, 51, 51, 51, 51, 21, 64, 51, 51, 51, 51, 51, 51, 21, 192}, false},
		{"1s2s10s", []interface{}{"a", "bb", "1234567890"},
			[]byte{97, 98, 98, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48}, false},
		{"III4s", []interface{}{1, 2, 4, "DUMP"},
			[]byte{1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 68, 85, 77, 80}, false},
	}
	for _, tt := range cases {
		got, err := StructsPack(tt.f, tt.a)
		if (err != nil) != tt.e {
			t.Errorf("%q. StructsPack() error = %v, wantErr %v", tt.f, err, tt.e)
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("%q. StructsPack() = %v, want %v", tt.f, got, tt.want)
		}
	}
}

func TestStructsUnpack(t *testing.T) {
	cases := []struct {
		f    string
		a    []byte
		want []interface{}
		e    bool
	}{
		{"??", []byte{1, 0}, []interface{}{true, false}, false},
		{"hhh", []byte{0, 0, 5, 0, 251, 255},
			[]interface{}{0, 5, -5}, false},
		{"HHH", []byte{0, 0, 5, 0, 252, 8},
			[]interface{}{0, 5, 2300}, false},
		{"iii", []byte{0, 0, 0, 0, 5, 0, 0, 0, 251, 255, 255, 255},
			[]interface{}{0, 5, -5}, false},
		{"III", []byte{0, 0, 0, 0, 5, 0, 0, 0, 252, 8, 0, 0},
			[]interface{}{0, 5, 2300}, false},
		{"fff",
			[]byte{0, 0, 0, 0, 154, 153, 169, 64, 154, 153, 169, 192},
			[]interface{}{float32(0.0), float32(5.3), float32(-5.3)}, false},
		{"ddd",
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 51, 51, 51, 51, 51, 51, 21, 64, 51, 51, 51, 51, 51, 51, 21, 192},
			[]interface{}{0.0, 5.3, -5.3}, false},
		{"1s2s10s",
			[]byte{97, 98, 98, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48},
			[]interface{}{"a", "bb", "1234567890"}, false},
		{"III4s",
			[]byte{1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 68, 85, 77, 80},
			[]interface{}{1, 2, 4, "DUMP"}, false},
	}

	for _, tt := range cases {
		got, err := StructsUnpack(tt.f, tt.a)
		if (err != nil) != tt.e {
			t.Errorf("%q. StructsUnpack() error = %v, wantErr %v", tt.f, err, tt.e)
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("%q. StructsUnpack() = %v, want %v", tt.f, got, tt.want)
		}
	}
}

func Test_buildFormatStringSliceFromString(t *testing.T) {
	cases := []struct {
		f    string
		want []string
	}{
		{"??", []string{"?", "?"}},
		{"hhh", []string{"h", "h", "h"}},
		{"1s2s10s", []string{"1s", "2s", "10s"}},
		{"III4s", []string{"I", "I", "I", "4s"}},
	}
	for _, tt := range cases {
		got := buildFormatSliceFromStringFormat(tt.f)
		if len(got) != len(tt.want) {
			t.Fatalf("%q. buildFormatStringSliceFromString() = %v, want %v", tt.f, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("%q. buildFormatStringSliceFromString() = %v, want %v", tt.f, got, tt.want)
			}
		}
	}
}
