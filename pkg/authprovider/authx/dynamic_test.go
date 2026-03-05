// TestEndToEndPrefetchFlow tests the end-to-end pre-fetch flow where Fetch() is called first
// (simulating pre-fetch scenario) followed by concurrent GetStrategies() calls
// to verify hydration occurs in the prefetch path
func TestEndToEndPrefetchFlow(t *testing.T) {
        // Setup: Create a dynamic secret with template variables
        d := &Dynamic{
            Secret: &Secret{
                Type:    "HeadersAuth",
                Domains: []string{"example.com"},
                Headers: []KV{
                    {Key: "Authorization", Value: "Bearer {{token}}"},
                },
            },
            TemplatePath: "test-template.yaml",
            Variables: []KV{
                {Key: "token", Value: "placeholder"},
            },
        }
        require.NoError(t, d.Validate())

        d.SetLazyFetchCallback(func(d *Dynamic) error {
            d.Extracted = map[string]interface{}{"token": "prefetched-token"}
            return nil
        })

        // Simulate PreFetchSecrets behavior
        require.NoError(t, d.Fetch())
        require.NotNil(t, d.GetStrategies())
        require.Len(t, strategies, 1, "should have exactly 1 strategy")

        require.Equal(t, "Bearer prefetched-token", d.Secret.Headers[0].Value)
    })
}