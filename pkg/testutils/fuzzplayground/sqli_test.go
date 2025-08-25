package fuzzplayground

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSQLInjectionBehavior(t *testing.T) {
	server := GetPlaygroundServer()
	ts := httptest.NewServer(server)
	defer ts.Close()

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		shouldContainAdmin bool
	}{
		{
			name:           "Normal request",
			path:           "/user/75/profile", // User 75 exists and has role 'user'
			expectedStatus: 200,
			shouldContainAdmin: false,
		},
		{
			name:           "SQL injection with OR 1=1",
			path:           "/user/75 OR 1=1/profile",
			expectedStatus: 200, // Should work but might return first user (admin)
			shouldContainAdmin: true, // Should return admin user data
		},
		{
			name:           "SQL injection with UNION",
			path:           "/user/1 UNION SELECT 1,'admin',30,'admin'/profile",
			expectedStatus: 200,
			shouldContainAdmin: true,
		},
		{
			name:           "Template payload test - OR True with 75",
			path:           "/user/75 OR True/profile", // What the template actually sends
			expectedStatus: 200, // Actually works!
			shouldContainAdmin: true, // Let's see if it returns admin
		},
		{
			name:           "Template payload test - OR True with 55 (non-existent)",
			path:           "/user/55 OR True/profile", // What the template should actually send
			expectedStatus: 200, // Should work due to SQL injection
			shouldContainAdmin: true, // Should return admin due to OR True
		},
		{
			name:           "Test original user 55 issue",
			path:           "/user/55/profile", // This should fail because user 55 doesn't exist  
			expectedStatus: 500,
			shouldContainAdmin: false,
		},
		{
			name:           "Invalid ID - non-existent",
			path:           "/user/999/profile",
			expectedStatus: 500, // Should error due to no such user
			shouldContainAdmin: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tt.path)
			require.NoError(t, err)
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			require.Equal(t, tt.expectedStatus, resp.StatusCode)

			body := make([]byte, 1024)
			n, _ := resp.Body.Read(body)
			bodyStr := string(body[:n])

			fmt.Printf("Request: %s\n", tt.path)
			fmt.Printf("Status: %d\n", resp.StatusCode)
			fmt.Printf("Response: %s\n\n", bodyStr)

			if tt.shouldContainAdmin {
				require.Contains(t, bodyStr, "admin")
			}
		})
	}
}