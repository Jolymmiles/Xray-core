// Package core provides an entry point to use Xray core functionalities.
//
// Xray makes it possible to accept incoming network connections with certain
// protocol, process the data, and send them through another connection with
// the same or a difference protocol on demand.
//
// It may be configured to work with multiple protocols at the same time, and
// uses the internal router to tunnel through different inbound and outbound
// connections.
package core

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/xtls/xray-core/common/serial"
)

var (
	Version_x byte = 26
	Version_y byte = 8
	Version_z byte = 26
)

// versionHHMM is the UTC hour and minute baked into Version().
const versionHHMM = 855

var (
	build    = "Custom"
	codename = "Xray, Penetrates Everything.(jesus)"
	intro    = "A unified platform for anti-censorship."
)

func init() {
	// Manually injected
	if build != "Custom" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	var isDirty bool
	var foundBuild bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if len(setting.Value) < 7 {
				return
			}
			build = setting.Value[:7]
			foundBuild = true
		case "vcs.modified":
			isDirty = setting.Value == "true"
		}
	}
	if isDirty && foundBuild {
		build += "-dirty"
	}
}

// Version returns year.month.day-HHMM in UTC so the panel string is semver-compatible.
// Numeric Version_x/y/z remain the protocol identity (REALITY session id).
func Version() string {
	return fmt.Sprintf("%v.%v.%v-%04d", Version_x, Version_y, Version_z, versionHHMM)
}

// VersionStatement returns a list of strings representing the full version info.
func VersionStatement() []string {
	return []string{
		serial.Concat("Xray ", Version(), " (", codename, ") ", build, " (", runtime.Version(), " ", runtime.GOOS, "/", runtime.GOARCH, ")"),
		intro,
	}
}
