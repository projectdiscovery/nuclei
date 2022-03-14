// Package automaticscan implements automatic technology based template
// execution for a nuclei instance.
//
// First wappalyzer based technology detection is performed and templates
// are executed based on the results found. The results of wappalyzer
// technology detection are lowercased and split on space characters in the name,
// which are then used as tags for the execution of the templates.
//
// The logic is very simple and can be further improved to increase the coverage of
// this mode of nuclei exection.
package automaticscan
