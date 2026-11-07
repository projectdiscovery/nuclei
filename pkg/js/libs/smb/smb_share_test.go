package smb

import (
	"testing"

	"github.com/stretchr/testify/require"
	zgrabsmb "github.com/zmap/zgrab2/lib/smb/smb"
)

func TestParseNTLMIdentity(t *testing.T) {
	domain, user := parseNTLMIdentity(`CORP\alice`)
	require.Equal(t, "CORP", domain)
	require.Equal(t, "alice", user)
}

func TestNormalizeSharePath(t *testing.T) {
	got, err := normalizeSharePath(`docs\a.txt`)
	require.NoError(t, err)
	require.Equal(t, "docs/a.txt", got)
	_, err = normalizeSharePath("../x")
	require.Error(t, err)
}

func TestRequireShareName(t *testing.T) {
	require.Error(t, requireShareName(""))
	require.Error(t, requireShareName("a/b"))
	require.NoError(t, requireShareName("backup"))
}

func TestProtocolInfoFromLog(t *testing.T) {
	info := protocolInfoFromLog(&zgrabsmb.SMBLog{
		SupportV1: true,
		HasNTLM:   true,
		Version: &zgrabsmb.SMBVersions{
			Major:     3,
			Minor:     1,
			VerString: "SMB 3.1.1",
		},
		NegotiationLog: &zgrabsmb.NegotiationLog{
			DialectRevision: zgrabsmb.DialectSmb_3_1_1,
		},
	})
	require.True(t, info.SMB1Supported)
	require.True(t, info.SMB2Supported)
	require.Equal(t, "SMB 3.1.1", info.Dialect)
}

func TestDialectName(t *testing.T) {
	require.Equal(t, "SMB 2.1", dialectName(zgrabsmb.DialectSmb_2_1))
	require.Equal(t, "", dialectName(0))
}
