package output

import (
	"testing"
)

func TestHoneypotTracker(t *testing.T) {
	// Create tracker with small capacity for testing
	tracker := NewHoneypotTracker(3)
	
	// Test 1: Adding sessions works
	t.Run("AddingSessions", func(t *testing.T) {
		hosts := []string{"host1", "host2", "host3"}
		templateID := "template1"
		
		for i, host := range hosts {
			isHoneypot, isFirstTime := tracker.AddSession(host, templateID)
			
			// Should not be honeypot with only 1 template
			if isHoneypot {
				t.Errorf("Host %s should not be honeypot with 1 template", host)
			}
			
			// Should not be first time honeypot detection
			if isFirstTime {
				t.Errorf("Host %s should not trigger first-time honeypot warning", host)
			}
			
			// Verify host is tracked
			session, exists := tracker.GetSession(host)
			if !exists {
				t.Errorf("Host %s should be tracked", host)
			}
			
			// Verify session data
			if len(session.TemplateIDs) != 1 {
				t.Errorf("Host %s should have 1 template, got %d", host, len(session.TemplateIDs))
			}
			
			// Verify order length
			stats, _, capacity := tracker.GetStats()
			if stats != i+1 {
				t.Errorf("Expected %d tracked hosts, got %d", i+1, stats)
			}
			
			// Verify capacity
			if capacity != 3 {
				t.Errorf("Expected capacity 3, got %d", capacity)
			}
		}
	})
	
	// Test 2: Accessing a session moves it to 'Most Recently Used'
	t.Run("MRUAccess", func(t *testing.T) {
		// Access host2 (should move to end)
		isHoneypot, isFirstTime := tracker.AddSession("host2", "template2")
		if isHoneypot || isFirstTime {
			t.Error("Accessing existing host should not trigger honeypot detection")
		}
		
		// Verify host2 session was updated
		session, exists := tracker.GetSession("host2")
		if !exists {
			t.Error("Host2 should still exist")
		}
		
		if len(session.TemplateIDs) != 2 {
			t.Errorf("Host2 should have 2 templates, got %d", len(session.TemplateIDs))
		}
		
		// Access host1 (should move to end)
		tracker.AddSession("host1", "template3")
		
		// Verify final order through LRU behavior
		// The order should now be: host3, host2, host1 (host1 most recent)
		// We can verify this by checking which host gets evicted next
		
		// Add a new host to trigger eviction
		tracker.AddSession("host4", "template1")
		
		// host3 should be evicted (oldest)
		_, exists = tracker.GetSession("host3")
		if exists {
			t.Error("host3 should have been evicted (oldest)")
		}
		
		// host1, host2, host4 should still exist
		for _, host := range []string{"host1", "host2", "host4"} {
			_, exists := tracker.GetSession(host)
			if !exists {
				t.Errorf("Host %s should still exist", host)
			}
		}
	})
	
	// Test 3: Adding a session beyond capacity evicts the 'Least Recently Used' one
	t.Run("LRUEviction", func(t *testing.T) {
		// Current state should have: host2, host1, host4 (host3 evicted)
		
		// Add host5 (should evict host2 - the oldest)
		isHoneypot, isFirstTime := tracker.AddSession("host5", "template1")
		if isHoneypot || isFirstTime {
			t.Error("Adding new host should not trigger honeypot detection")
		}
		
		// Verify capacity is maintained
		stats, _, capacity := tracker.GetStats()
		if stats != 3 {
			t.Errorf("Expected 3 tracked hosts after eviction, got %d", stats)
		}
		if capacity != 3 {
			t.Errorf("Expected capacity 3, got %d", capacity)
		}
		
		// Verify host2 was evicted (oldest)
		_, exists := tracker.GetSession("host2")
		if exists {
			t.Error("host2 should have been evicted (oldest)")
		}
		
		// Verify remaining hosts exist
		remainingHosts := []string{"host1", "host4", "host5"}
		for _, host := range remainingHosts {
			_, exists := tracker.GetSession(host)
			if !exists {
				t.Errorf("Host %s should still exist after eviction", host)
			}
		}
		
		// Verify order is correct: host4, host1, host5 (host5 most recent)
		// Add host6 to test order again
		tracker.AddSession("host6", "template1")
		
		// host4 should be evicted (oldest)
		_, exists = tracker.GetSession("host4")
		if exists {
			t.Error("host4 should have been evicted (oldest)")
		}
		
		// Final hosts should be: host1, host5, host6
		finalHosts := []string{"host1", "host5", "host6"}
		for _, host := range finalHosts {
			_, exists := tracker.GetSession(host)
			if !exists {
				t.Errorf("Host %s should exist in final state", host)
			}
		}
	})
	
	// Test 4: Honeypot detection functionality
	t.Run("HoneypotDetection", func(t *testing.T) {
		// Clear tracker for clean test
		tracker.Clear()
		
		host := "test-host"
		
		// Add templates until honeypot threshold (10+ templates)
		for i := 0; i < 15; i++ {
			templateID := "template" + string(rune('A'+i))
			isHoneypot, isFirstTime := tracker.AddSession(host, templateID)
			
			if i < 10 {
				// Should not be honeypot before threshold
				if isHoneypot {
					t.Errorf("Host should not be honeypot with %d templates", i+1)
				}
				if isFirstTime {
					t.Error("Should not trigger first-time honeypot warning before threshold")
				}
			} else if i == 10 {
				// Should become honeypot at threshold
				if !isHoneypot {
					t.Error("Host should be detected as honeypot at threshold")
				}
				if !isFirstTime {
					t.Error("Should trigger first-time honeypot warning at threshold")
				}
			} else {
				// Should remain honeypot but not first-time warning
				if !isHoneypot {
					t.Error("Host should remain honeypot after threshold")
				}
				if isFirstTime {
					t.Error("Should not trigger first-time honeypot warning after first detection")
				}
			}
		}
		
		// Verify session data
		session, exists := tracker.GetSession(host)
		if !exists {
			t.Error("Host should exist")
		}
		
		if len(session.TemplateIDs) != 15 {
			t.Errorf("Host should have 15 templates, got %d", len(session.TemplateIDs))
		}
		
		// Verify timing
		if session.FirstSeen.After(session.LastSeen) {
			t.Error("FirstSeen should not be after LastSeen")
		}
	})
	
	// Test 5: Edge cases and error handling
	t.Run("EdgeCases", func(t *testing.T) {
		tracker.Clear()
		
		// Test empty host
		isHoneypot, isFirstTime := tracker.AddSession("", "template1")
		if isHoneypot || isFirstTime {
			t.Error("Empty host should return false, false")
		}
		
		// Test whitespace-only host
		isHoneypot, isFirstTime = tracker.AddSession("   ", "template1")
		if isHoneypot || isFirstTime {
			t.Error("Whitespace-only host should return false, false")
		}
		
		// Test invalid URLs
		invalidHosts := []string{
			"http://[invalid-ipv6",
			"ftp://example.com",
			"not-a-url",
		}
		
		for _, host := range invalidHosts {
			isHoneypot, isFirstTime = tracker.AddSession(host, "template1")
			if isHoneypot || isFirstTime {
				t.Errorf("Invalid host %s should return false, false", host)
			}
		}
		
		// Verify no hosts were tracked
		stats, _, _ := tracker.GetStats()
		if stats != 0 {
			t.Errorf("Expected no hosts tracked with invalid inputs, got %d", stats)
		}
	})
	
	// Test 6: URL parsing and normalization
	t.Run("URLParsing", func(t *testing.T) {
		tracker.Clear()
		
		testCases := []struct {
			input    string
			expected string
		}{
			{"example.com", "example.com"},
			{"http://example.com", "example.com"},
			{"https://example.com:8080", "example.com"},
			{"example.com/path", "example.com"},
			{"http://example.com/path?query=1", "example.com"},
		}
		
		for _, tc := range testCases {
			isHoneypot, isFirstTime := tracker.AddSession(tc.input, "template1")
			
			if isHoneypot || isFirstTime {
				t.Errorf("Valid host %s should not trigger honeypot on first access", tc.input)
			}
			
			// Verify host was tracked with correct hostname
			session, exists := tracker.GetSession(tc.expected)
			if !exists {
				t.Errorf("Host %s should be tracked as %s", tc.input, tc.expected)
			}
			
			if len(session.TemplateIDs) != 1 {
				t.Errorf("Host %s should have 1 template", tc.expected)
			}
		}
	})
	
	// Test 7: Statistics and capacity
	t.Run("Statistics", func(t *testing.T) {
		tracker.Clear()
		
		// Initial stats
		stats, warned, capacity := tracker.GetStats()
		if stats != 0 || warned != 0 || capacity != 3 {
			t.Errorf("Initial stats should be (0, 0, 3), got (%d, %d, %d)", stats, warned, capacity)
		}
		
		// Add some hosts
		tracker.AddSession("host1", "template1")
		tracker.AddSession("host2", "template1")
		
		stats, warned, capacity = tracker.GetStats()
		if stats != 2 || warned != 0 || capacity != 3 {
			t.Errorf("Stats after 2 hosts should be (2, 0, 3), got (%d, %d, %d)", stats, warned, capacity)
		}
		
		// Trigger honeypot detection
		for i := 0; i < 11; i++ {
			tracker.AddSession("host1", "template"+string(rune('A'+i)))
		}
		
		stats, warned, capacity = tracker.GetStats()
		if stats != 2 || warned != 1 || capacity != 3 {
			t.Errorf("Stats after honeypot should be (2, 1, 3), got (%d, %d, %d)", stats, warned, capacity)
		}
	})
}
