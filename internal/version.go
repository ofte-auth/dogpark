package internal

import (
	"fmt"
)

var (
	name      string = "Ofte Dogpark"
	version   string = "v0.9.0"
	buildDate string = ""
	commit    string = ""
)

// Version returns the version string.
func Version() string {
	return fmt.Sprintf("%s %s", name, version)
}

// VersionVerbose return the verbose version string.
func VersionVerbose() string {
	return fmt.Sprintf("%s %s %s %s", name, version, buildDate, commit)
}
