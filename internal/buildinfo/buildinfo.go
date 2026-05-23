// Package buildinfo exposes the binary's version + VCS metadata so the
// /auth/me response (and any future ops endpoint) can report a single
// authoritative answer to "which build is running here?"
//
// Two layers of provenance:
//
//   - GoReleaser builds (the prod path) inject Version via -ldflags from
//     the git tag — see .goreleaser.yaml. That's the human-meaningful
//     answer: "v0.1.2".
//   - Local `go build` / `go run` (the dev path) leaves Version="dev" and
//     we fall back to runtime/debug.ReadBuildInfo for the VCS commit and
//     dirty flag. Go embeds these automatically when building from a git
//     working tree, no extra flags needed.
//
// The combined Info is stable to render in a UI badge: "v0.1.2 (abc1234)"
// for a tagged release, "dev (abc1234*)" for an uncommitted local build,
// or just "dev" if even VCS info is missing (e.g. `go install` from a
// non-git source).
package buildinfo

import "runtime/debug"

// Version is overwritten at link time by GoReleaser via
// `-X github.com/forgeutah/forge-proxy/internal/buildinfo.Version=...`.
// The "dev" default is what local builds see.
var Version = "dev"

// Info is the small struct the /auth/me handler embeds verbatim. JSON
// tags are snake_case for consistency with the rest of that response.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Dirty   bool   `json:"dirty,omitempty"`
}

// Get reads runtime build info and combines it with the link-time
// Version. Cheap enough to call per-request — debug.ReadBuildInfo
// reads from a struct already embedded in the binary, no I/O.
func Get() Info {
	info := Info{Version: Version}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			// Trim to 7 chars (git short-SHA convention). A guard
			// against shorter values keeps us safe if some future VCS
			// integration reports a non-SHA identifier.
			if len(s.Value) >= 7 {
				info.Commit = s.Value[:7]
			} else {
				info.Commit = s.Value
			}
		case "vcs.modified":
			info.Dirty = s.Value == "true"
		}
	}
	return info
}
