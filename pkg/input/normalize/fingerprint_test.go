package normalize

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPatternGroupsIdentifiers(t *testing.T) {
	f := NewFingerprinter(1)
	base := f.Pattern("http://acme.test/user/1/profile")
	for _, raw := range []string{
		"http://acme.test/user/2/profile",
		"http://acme.test/user/99999/profile",
	} {
		require.Equal(t, base, f.Pattern(raw), "numeric ids are the same shape")
	}
	require.Contains(t, base, placeholderNum)
}

func TestPatternGroupsUUIDsHashesAndDates(t *testing.T) {
	f := NewFingerprinter(1)
	require.Contains(t, f.Pattern("http://acme.test/o/3f2504e0-4f89-11d3-9a0c-0305e82c3301"), placeholderUUID)
	require.Contains(t, f.Pattern("http://acme.test/a/d41d8cd98f00b204e9800998ecf8427e"), placeholderHash)
	require.Contains(t, f.Pattern("http://acme.test/posts/2024-05-01"), placeholderDate)
	// a date spread across positions is already grouped as numeric segments
	require.Equal(t, "acme.test/posts/{num}/{num}", f.Pattern("http://acme.test/posts/2024/05"))
}

func TestPatternKeepsRouteNames(t *testing.T) {
	f := NewFingerprinter(1)
	require.NotEqual(t, f.Pattern("http://acme.test/admin"), f.Pattern("http://acme.test/login"),
		"route names are the structure, not identifiers within it")
}

func TestPatternDropsQueryValuesButKeepsSortedNames(t *testing.T) {
	f := NewFingerprinter(1)
	a := f.Pattern("http://acme.test/search?q=admin&page=2")
	b := f.Pattern("http://acme.test/search?page=9&q=root")
	require.Equal(t, a, b, "same parameters in a different order with different values is one shape")
	require.Contains(t, a, "page&q")
	require.NotContains(t, a, "admin")

	require.NotEqual(t, a, f.Pattern("http://acme.test/search?q=admin"), "a different parameter set is a different shape")
}

func TestPatternCollapsesHighCardinalityPosition(t *testing.T) {
	f := NewFingerprinter(1)
	f.CollapseAfter = 5
	// slugs have no recognisable shape, so the position itself is what gives
	// them away once it has held enough distinct values
	for i := 0; i < 5; i++ {
		f.Pattern(fmt.Sprintf("http://acme.test/blog/%s-post", []string{"alpha", "beta", "gamma", "delta", "epsilon"}[i]))
	}
	require.Contains(t, f.Pattern("http://acme.test/blog/zeta-post"), placeholderVar)
	// a different host is tracked separately
	require.NotContains(t, f.Pattern("http://other.test/blog/zeta-post"), placeholderVar)
}

func TestCollapseStaysInsideTheParentPath(t *testing.T) {
	f := NewFingerprinter(1)
	f.CollapseAfter = 3
	require.Equal(t, "acme.test/blog/one", f.Pattern("http://acme.test/blog/one"))
	require.Equal(t, "acme.test/blog/two", f.Pattern("http://acme.test/blog/two"))
	require.Equal(t, "acme.test/blog/{var}", f.Pattern("http://acme.test/blog/three"))

	// same index, different parent: a busy /blog/<slug> must not collapse /admin/<name>
	require.Equal(t, "acme.test/admin/a", f.Pattern("http://acme.test/admin/a"))
	require.Equal(t, "acme.test/admin/b", f.Pattern("http://acme.test/admin/b"))
	require.True(t, f.Accept("http://acme.test/admin/a"))
	require.True(t, f.Accept("http://acme.test/admin/b"), "a different parent still has its own cap")
}

func TestAcceptKeepsUpToTheCap(t *testing.T) {
	f := NewFingerprinter(2)
	require.True(t, f.Accept("http://acme.test/user/1"))
	require.True(t, f.Accept("http://acme.test/user/2"))
	require.False(t, f.Accept("http://acme.test/user/3"), "past the cap the pattern is already covered")
	require.True(t, f.Accept("http://acme.test/admin"), "a different pattern has its own budget")
}

// Off by default: dropping a target means never scanning it, so it has to be
// asked for.
func TestDisabledFingerprinterKeepsEverything(t *testing.T) {
	f := NewFingerprinter(0)
	require.False(t, f.Enabled())
	for i := 0; i < 100; i++ {
		require.True(t, f.Accept(fmt.Sprintf("http://acme.test/user/%d", i)))
	}
	var nilF *Fingerprinter
	require.False(t, nilF.Enabled())
	require.True(t, nilF.Accept("http://acme.test/user/1"))
}

func TestAcceptKeepsNonURLTargets(t *testing.T) {
	f := NewFingerprinter(1)
	require.True(t, f.Accept("acme.test"))
	require.True(t, f.Accept("not a url"))
	require.True(t, f.Accept("not a url"), "a value with no pattern is never grouped away")
}
