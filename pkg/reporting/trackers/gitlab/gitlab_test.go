package gitlab

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeIssue struct {
	ID    int64  `json:"id"`
	IID   int64  `json:"iid"`
	Title string `json:"title"`
}

// fakeGitLab serves the GitLab API endpoints that findIssueByTitle uses. Like
// GitLab, it caps per_page at maxPerPage and names the next page in the
// X-Next-Page header, which is empty on the last page. Every issue counts as
// a search hit, which leaves the exact title match to the tracker.
type fakeGitLab struct {
	issues     []fakeIssue
	maxPerPage int

	mu    sync.Mutex
	pages []int
}

func newFakeGitLab(issueCount, maxPerPage int) *fakeGitLab {
	f := &fakeGitLab{maxPerPage: maxPerPage}
	for n := 1; n <= issueCount; n++ {
		f.issues = append(f.issues, fakeIssue{ID: int64(n), IID: int64(n), Title: fmt.Sprintf("issue %d", n)})
	}
	return f
}

func (f *fakeGitLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v4/user":
		_, _ = w.Write([]byte(`{"id":1}`))
	case "/api/v4/projects/1234/issues":
		f.listIssues(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGitLab) listIssues(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage <= 0 || perPage > f.maxPerPage {
		perPage = f.maxPerPage
	}

	f.mu.Lock()
	f.pages = append(f.pages, page)
	f.mu.Unlock()

	nextPage := ""
	if page*perPage < len(f.issues) {
		nextPage = strconv.Itoa(page + 1)
	}
	w.Header().Set("X-Next-Page", nextPage)

	start := min((page-1)*perPage, len(f.issues))
	end := min(start+perPage, len(f.issues))
	_ = json.NewEncoder(w).Encode(f.issues[start:end])
}

func (f *fakeGitLab) requestedPages() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.pages)
}

func TestFindIssueByTitle(t *testing.T) {
	tests := []struct {
		name      string
		title     string
		maxPages  int
		wantIID   int64
		wantPages []int
	}{
		{
			name:      "match after a server-capped first page",
			title:     "issue 110",
			wantIID:   110,
			wantPages: []int{1, 2},
		},
		{
			name:      "no match checks every page once",
			title:     "missing",
			wantPages: []int{1, 2},
		},
		{
			name:      "max pages stops the search",
			title:     "issue 110",
			maxPages:  1,
			wantPages: []int{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// GitLab caps per_page at 100, so a configured page size of
			// 150 still splits 120 issues into two pages.
			fake := newFakeGitLab(120, 100)
			server := httptest.NewServer(fake)
			t.Cleanup(server.Close)

			integration, err := New(&Options{
				BaseURL:                server.URL,
				Token:                  "token",
				ProjectName:            "1234",
				DuplicateIssuePageSize: 150,
				DuplicateIssueMaxPages: tt.maxPages,
			})
			require.NoError(t, err)

			issue, err := integration.findIssueByTitle(tt.title)
			require.NoError(t, err)
			if tt.wantIID == 0 {
				require.Nil(t, issue)
			} else {
				require.NotNil(t, issue)
				require.Equal(t, tt.wantIID, issue.IID)
			}
			require.Equal(t, tt.wantPages, fake.requestedPages())
		})
	}
}
