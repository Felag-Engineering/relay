package main

import "runtime/debug"

// versionString reports relayctl's build version.
//
// It reads the Go build info rather than taking a -ldflags stamp of its own:
// relayctl is a workstation tool, not a fleet participant, so nothing gates on
// its version the way the Relay's minimum-daemon-version gate does on the
// daemon's (ADR-0014). "Which build is this" is all an operator needs, and
// build info answers it for `go install` and released binaries alike.
func versionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "relayctl (version unknown)"
	}
	v := info.Main.Version
	var revision string
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			revision = s.Value
		}
	}
	if revision != "" {
		if len(revision) > 12 {
			revision = revision[:12]
		}
		return "relayctl " + v + " (" + revision + ")"
	}
	return "relayctl " + v
}
