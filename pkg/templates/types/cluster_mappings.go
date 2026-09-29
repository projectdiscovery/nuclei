package types

// ClusterMappingsMap wraps cluster ID to template IDs mapping
type ClusterMappingsMap struct {
	Map map[string][]string
}

// NewClusterMappingsMap creates a new ClusterMappingsMap from an existing map
func NewClusterMappingsMap(m map[string][]string) *ClusterMappingsMap {
	return &ClusterMappingsMap{Map: m}
}

// Get returns the template IDs for a given cluster ID, or nil, false if the receiver or Map is nil
func (c *ClusterMappingsMap) Get(clusterID string) ([]string, bool) {
	if c == nil || c.Map == nil {
		return nil, false
	}
	v, ok := c.Map[clusterID]
	return v, ok
}

// GetAll returns a copy of the entire map, or an empty map if the receiver or Map is nil
func (c *ClusterMappingsMap) GetAll() map[string][]string {
	if c == nil || c.Map == nil {
		return make(map[string][]string)
	}
	result := make(map[string][]string, len(c.Map))
	for k, v := range c.Map {
		result[k] = append([]string{}, v...)
	}
	return result
}

// Copy returns a deep copy of the ClusterMappingsMap, or nil if the receiver is nil
func (c *ClusterMappingsMap) Copy() *ClusterMappingsMap {
	if c == nil {
		return nil
	}
	return NewClusterMappingsMap(c.GetAll())
}
