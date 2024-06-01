package logger

import "fmt"

var verbose *bool

// SetVerbose sets the verbosity level for logging.
func SetVerbose(v *bool) {
	verbose = v
}

// LogDebug logs debug messages if verbose flag is set
func LogDebug(msg string, args ...interface{}) {
	if *verbose {
		fmt.Printf("[DEBUG] "+msg+"\n", args...)
	}
}
