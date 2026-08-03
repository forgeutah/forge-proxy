package config

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestEnvExampleUpstreamsParses pins the shipped example against the real
// parser. A docs example that fails to boot is worse than no example.
func TestEnvExampleUpstreamsParses(t *testing.T) {
	f, err := os.Open("../../.env.example")
	if err != nil {
		t.Fatalf("open .env.example: %v", err)
	}
	defer f.Close()

	var raw string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "UPSTREAMS="); ok {
			raw = v
			break
		}
	}
	if raw == "" {
		t.Fatal("no UPSTREAMS line found in .env.example")
	}

	m, err := parseUpstreams(raw)
	if err != nil {
		t.Fatalf("shipped .env.example UPSTREAMS does not parse: %v", err)
	}
	if len(m) < 2 {
		t.Errorf("example should show %d+ entries, got %d", 2, len(m))
	}

	var sawGated, sawUngated bool
	for _, u := range m {
		if u.Gated() {
			sawGated = true
		} else {
			sawUngated = true
		}
	}
	if !sawGated || !sawUngated {
		t.Error("example should demonstrate both a gated and an ungated entry")
	}
}
