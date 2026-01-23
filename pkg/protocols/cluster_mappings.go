package protocols

import "sync"

// ClusterMappingsMap is a thread-safe map for cluster ID to template IDs mapping
type ClusterMappingsMap struct {
	mu  sync.RWMutex
	Map map[string][]string
}

// NewClusterMappingsMap creates a new ClusterMappingsMap from an existing map
func NewClusterMappingsMap(m map[string][]string) *ClusterMappingsMap {
	return &ClusterMappingsMap{Map: m}
}

// Get returns the template IDs for a given cluster ID
func (c *ClusterMappingsMap) Get(clusterID string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.Map[clusterID]
	return v, ok
}

// GetAll returns a copy of the entire map
func (c *ClusterMappingsMap) GetAll() map[string][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string][]string, len(c.Map))
	for k, v := range c.Map {
		result[k] = append([]string{}, v...)
	}
	return result
}
