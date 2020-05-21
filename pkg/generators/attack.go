package generators

// Type is type of attack
type Type int

const (
	// Sniper attack - each variable replaced with values at a time
	Sniper Type = iota + 1
	// PitchFork attack - Each variable replaced with positional value in multiple wordlists
	PitchFork
	// ClusterBomb attack - Generate all possible combinations of values
	ClusterBomb
)

// AttackTypes is an table for conversion of attack type from string.
var AttackTypes = map[string]Type{
	"sniper":      Sniper,
	"pitchfork":   PitchFork,
	"clusterbomb": ClusterBomb,
}
