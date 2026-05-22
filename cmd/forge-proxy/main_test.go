package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

// fakePinger is a pinger stub for the /readyz tests.
type fakePinger struct{ err error }

func (f fakePinger) PingContext(_ context.Context) error { return f.err }

// fakeOIDC implements readinessOIDC.
type fakeOIDC struct{ ready bool }

func (f fakeOIDC) IsReady() bool { return f.ready }

// fakeSweeper implements readinessSweeper.
type fakeSweeper struct{ last time.Time }

func (f fakeSweeper) LastSuccess() time.Time { return f.last }

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	healthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body, _ := io.ReadAll(rec.Body)
	if got, want := string(body), "ok"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("content-type = %q, want text/plain", got)
	}
}

func TestReadyz_HealthyReturns200(t *testing.T) {
	h := readyzHandler(
		fakePinger{},
		fakePinger{},
		fakeOIDC{ready: true},
		fakeSweeper{last: time.Now()},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "ready") {
		t.Fatalf("body = %q, want to contain 'ready'", string(body))
	}
}

func TestReadyz_OIDCNotReadyReturns503(t *testing.T) {
	h := readyzHandler(
		fakePinger{},
		fakePinger{},
		fakeOIDC{ready: false},
		fakeSweeper{},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "oidc") {
		t.Fatalf("body = %q, want to mention oidc", string(body))
	}
}

func TestReadyz_DBPingFailureReturns503(t *testing.T) {
	h := readyzHandler(
		fakePinger{err: errors.New("writer down")},
		fakePinger{},
		fakeOIDC{ready: true},
		fakeSweeper{last: time.Now()},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "writer db") {
		t.Fatalf("body = %q, want to mention writer db", string(body))
	}
}

func TestReadyz_ColdStartSweeperZeroIsAcceptable(t *testing.T) {
	// LastSuccess().IsZero() means "sweeper has not yet completed a run."
	// The handler tolerates this so /readyz doesn't fail during the first
	// hour of life. Anything else returning healthy keeps the response 200.
	h := readyzHandler(
		fakePinger{},
		fakePinger{},
		fakeOIDC{ready: true},
		fakeSweeper{last: time.Time{}},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (cold-start carve-out)", rec.Code)
	}
}

func TestReadyz_StaleSweeperReturns503(t *testing.T) {
	h := readyzHandler(
		fakePinger{},
		fakePinger{},
		fakeOIDC{ready: true},
		fakeSweeper{last: time.Now().Add(-3 * time.Hour)},
	)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (stale sweeper)", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "sweeper") {
		t.Fatalf("body = %q, want to mention sweeper", string(body))
	}
}

// TestHostMatches pins the dispatcher behaviour: case-insensitive Host
// comparison with port stripping. The auth host wins for matching inbound
// values; everything else falls through to the proxy.
func TestHostMatches(t *testing.T) {
	cases := []struct {
		inbound  string
		authHost string
		want     bool
	}{
		{"auth.forgeutah.tech", "auth.forgeutah.tech", true},
		{"AUTH.forgeutah.tech", "auth.forgeutah.tech", true},
		{"auth.forgeutah.tech:8080", "auth.forgeutah.tech", true},
		{"deuce.forgeutah.tech", "auth.forgeutah.tech", false},
		{"auth.forgeutah.tech.evil.com", "auth.forgeutah.tech", false},
		{"", "auth.forgeutah.tech", false},
	}
	for _, tc := range cases {
		if got := hostMatches(tc.inbound, tc.authHost); got != tc.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", tc.inbound, tc.authHost, got, tc.want)
		}
	}
}

// TestExtractEnvFileFlag pins the global-flag parser used in main() to
// strip --env-file before subcommand dispatch. The flag must:
//   - Recognise both `--env-file <path>` (space-separated) and
//     `--env-file=<path>` (equals form)
//   - Only fire when it appears as the FIRST arg (admin subcommand flags
//     must not collide)
//   - Reject missing or empty path values with a clear error
//   - Pass through args verbatim when the flag is absent
func TestExtractEnvFileFlag(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantArgs  []string
		wantFile  string
		wantError bool
	}{
		{
			name:     "absent",
			args:     []string{"admin", "list-users"},
			wantArgs: []string{"admin", "list-users"},
			wantFile: "",
		},
		{
			name:     "empty",
			args:     nil,
			wantArgs: nil,
			wantFile: "",
		},
		{
			name:     "space form",
			args:     []string{"--env-file", "/etc/forge.env"},
			wantArgs: []string{},
			wantFile: "/etc/forge.env",
		},
		{
			name:     "equals form",
			args:     []string{"--env-file=/etc/forge.env"},
			wantArgs: []string{},
			wantFile: "/etc/forge.env",
		},
		{
			name:     "space form followed by admin subcommand",
			args:     []string{"--env-file", "/etc/forge.env", "admin", "list-users"},
			wantArgs: []string{"admin", "list-users"},
			wantFile: "/etc/forge.env",
		},
		{
			name:     "equals form followed by admin subcommand",
			args:     []string{"--env-file=/etc/forge.env", "admin", "set-roles", "user@example.com", "admin"},
			wantArgs: []string{"admin", "set-roles", "user@example.com", "admin"},
			wantFile: "/etc/forge.env",
		},
		{
			name:      "space form with no path",
			args:      []string{"--env-file"},
			wantError: true,
		},
		{
			name:      "equals form with empty value",
			args:      []string{"--env-file="},
			wantError: true,
		},
		{
			name:     "flag in non-leading position is left alone",
			args:     []string{"admin", "--env-file", "/etc/forge.env"},
			wantArgs: []string{"admin", "--env-file", "/etc/forge.env"},
			wantFile: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotArgs, gotFile, err := extractEnvFileFlag(tc.args)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error, got args=%v file=%q", gotArgs, gotFile)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotFile != tc.wantFile {
				t.Errorf("envFile = %q, want %q", gotFile, tc.wantFile)
			}
			if !slicesEqual(gotArgs, tc.wantArgs) {
				t.Errorf("args = %v, want %v", gotArgs, tc.wantArgs)
			}
		})
	}
}

// TestExtractValueFlag pins the generic value-flag parser used for
// --pid-file and --log-file. Same shape as extractEnvFileFlag but
// parameterised on the flag name.
func TestExtractValueFlag(t *testing.T) {
	cases := []struct {
		name      string
		flag      string
		args      []string
		wantArgs  []string
		wantValue string
		wantError bool
	}{
		{
			name:     "absent",
			flag:     "--pid-file",
			args:     []string{"admin", "list-users"},
			wantArgs: []string{"admin", "list-users"},
		},
		{
			name:      "space form",
			flag:      "--pid-file",
			args:      []string{"--pid-file", "/var/run/forge.pid"},
			wantArgs:  []string{},
			wantValue: "/var/run/forge.pid",
		},
		{
			name:      "equals form",
			flag:      "--log-file",
			args:      []string{"--log-file=/var/log/forge.log", "admin"},
			wantArgs:  []string{"admin"},
			wantValue: "/var/log/forge.log",
		},
		{
			name:      "missing value (space form)",
			flag:      "--pid-file",
			args:      []string{"--pid-file"},
			wantError: true,
		},
		{
			name:      "empty value (equals form)",
			flag:      "--pid-file",
			args:      []string{"--pid-file="},
			wantError: true,
		},
		{
			name:     "not in leading position is ignored",
			flag:     "--pid-file",
			args:     []string{"admin", "--pid-file", "/x"},
			wantArgs: []string{"admin", "--pid-file", "/x"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotArgs, gotValue, err := extractValueFlag(tc.args, tc.flag)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error, got args=%v value=%q", gotArgs, gotValue)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotValue != tc.wantValue {
				t.Errorf("value = %q, want %q", gotValue, tc.wantValue)
			}
			if !slicesEqual(gotArgs, tc.wantArgs) {
				t.Errorf("args = %v, want %v", gotArgs, tc.wantArgs)
			}
		})
	}
}

// TestExtractBoolFlag pins the leading-position boolean-flag parser used
// for --daemon. Bools have no value; presence is the signal.
func TestExtractBoolFlag(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		flag     string
		wantArgs []string
		wantOn   bool
	}{
		{"absent", []string{"admin", "list-users"}, "--daemon", []string{"admin", "list-users"}, false},
		{"present alone", []string{"--daemon"}, "--daemon", []string{}, true},
		{"present before subcommand", []string{"--daemon", "admin"}, "--daemon", []string{"admin"}, true},
		{"in non-leading position is ignored", []string{"admin", "--daemon"}, "--daemon", []string{"admin", "--daemon"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotArgs, gotOn := extractBoolFlag(tc.args, tc.flag)
			if gotOn != tc.wantOn {
				t.Errorf("on = %v, want %v", gotOn, tc.wantOn)
			}
			if !slicesEqual(gotArgs, tc.wantArgs) {
				t.Errorf("args = %v, want %v", gotArgs, tc.wantArgs)
			}
		})
	}
}

// TestRebuildChildArgs verifies the args slice the daemon child receives
// when re-execed. --env-file is forwarded so the child can re-load the
// same file; --daemon / --pid-file / --log-file are stripped (they're
// parent-only).
func TestRebuildChildArgs(t *testing.T) {
	cases := []struct {
		name      string
		envFile   string
		remaining []string
		want      []string
	}{
		{"no env file, no remaining args", "", nil, []string{}},
		{"env file forwarded", "/etc/forge.env", nil, []string{"--env-file", "/etc/forge.env"}},
		{
			name:      "env file + remaining args",
			envFile:   "/etc/forge.env",
			remaining: []string{"admin", "list-users"},
			want:      []string{"--env-file", "/etc/forge.env", "admin", "list-users"},
		},
		{
			name:      "no env file, remaining args only",
			envFile:   "",
			remaining: []string{"admin", "list-users"},
			want:      []string{"admin", "list-users"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rebuildChildArgs(tc.envFile, tc.remaining)
			if !slicesEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsDaemonChild pins the marker-env check that prevents an infinite
// re-exec loop. The child sees the marker env and skips the daemonize
// branch entirely; the parent (no marker) does the fork.
func TestIsDaemonChild(t *testing.T) {
	t.Setenv(daemonMarkerEnv, "")
	if isDaemonChild() {
		t.Error("isDaemonChild() should be false when marker env is empty")
	}
	t.Setenv(daemonMarkerEnv, "1")
	if !isDaemonChild() {
		t.Error("isDaemonChild() should be true when marker env is '1'")
	}
	t.Setenv(daemonMarkerEnv, "0")
	if isDaemonChild() {
		t.Error("isDaemonChild() should be false when marker env is '0' (only '1' counts)")
	}
}

// TestCheckExistingPIDFile pins the three branches: no file (proceed),
// stale PID (proceed), live PID (refuse).
func TestCheckExistingPIDFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("no file", func(t *testing.T) {
		if err := checkExistingPIDFile(dir + "/missing.pid"); err != nil {
			t.Errorf("expected nil for missing file, got %v", err)
		}
	})

	t.Run("stale pid", func(t *testing.T) {
		p := dir + "/stale.pid"
		// PID 0 is invalid; FindProcess + signal(0) will reject. Some
		// kernels return ESRCH for any obviously-dead PID — 0 or a
		// huge unlikely-to-be-allocated value both serve.
		if err := os.WriteFile(p, []byte("999999999\n"), 0o644); err != nil {
			t.Fatalf("write stale pid: %v", err)
		}
		if err := checkExistingPIDFile(p); err != nil {
			t.Errorf("expected nil for stale pid, got %v", err)
		}
	})

	t.Run("malformed pid", func(t *testing.T) {
		p := dir + "/junk.pid"
		if err := os.WriteFile(p, []byte("not-a-pid\n"), 0o644); err != nil {
			t.Fatalf("write junk pid: %v", err)
		}
		if err := checkExistingPIDFile(p); err != nil {
			t.Errorf("expected nil for malformed pid (treated as stale), got %v", err)
		}
	})

	t.Run("live pid (our own pid)", func(t *testing.T) {
		p := dir + "/live.pid"
		if err := os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			t.Fatalf("write live pid: %v", err)
		}
		err := checkExistingPIDFile(p)
		if err == nil {
			t.Error("expected error for live pid, got nil")
		}
	})
}

// TestRenderSystemdUnit verifies the unit template renders with the
// expected substitutions. The actual systemctl call is out of test
// scope — that needs root + systemd, neither is reasonable to assume.
func TestRenderSystemdUnit(t *testing.T) {
	params := systemdSetupParams{
		User:       "forge-proxy",
		Group:      "forge-proxy",
		BinaryPath: "/opt/forge/forge-proxy",
		EnvFile:    "/etc/forge-proxy.env",
		DataDir:    "/var/lib/forge-proxy",
		UnitPath:   "/etc/systemd/system/forge-proxy.service",
	}
	out, err := renderSystemdUnit(params)
	if err != nil {
		t.Fatalf("renderSystemdUnit: %v", err)
	}

	expectedSubstrings := []string{
		"User=forge-proxy",
		"Group=forge-proxy",
		"EnvironmentFile=/etc/forge-proxy.env",
		"ExecStart=/opt/forge/forge-proxy",
		"ReadWritePaths=/var/lib/forge-proxy",
		// Hardening directives that should always be present.
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"PrivateTmp=true",
		"WantedBy=multi-user.target",
	}
	for _, want := range expectedSubstrings {
		if !strings.Contains(out, want) {
			t.Errorf("rendered unit missing %q", want)
		}
	}
}

// TestDefaultSystemdParams verifies the binary path is taken from the
// running executable, not hardcoded. Lets `forge-proxy setup systemd`
// work correctly when installed somewhere non-standard.
func TestDefaultSystemdParams(t *testing.T) {
	params, err := defaultSystemdParams()
	if err != nil {
		t.Fatalf("defaultSystemdParams: %v", err)
	}
	if params.BinaryPath == "" {
		t.Error("BinaryPath should not be empty")
	}
	if params.User != "forge-proxy" || params.Group != "forge-proxy" {
		t.Errorf("user/group = %s/%s, want forge-proxy/forge-proxy", params.User, params.Group)
	}
	if params.EnvFile != "/etc/forge-proxy.env" {
		t.Errorf("EnvFile = %q, want /etc/forge-proxy.env", params.EnvFile)
	}
}

// TestDefaultEnvFilePath verifies the auto-discovery walk used when
// --env-file isn't explicitly passed. The contract:
//   - FORGE_PROXY_ENV_FILE override wins if it points at an existing file
//   - First existing candidate in the default search path is returned
//   - "" returned when no candidate exists (caller falls back to process
//     env only — matches the systemd EnvironmentFile= case)
func TestDefaultEnvFilePath(t *testing.T) {
	dir := t.TempDir()
	override := dir + "/override.env"
	if err := os.WriteFile(override, []byte("X=1\n"), 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}

	// HOME-rooted candidate that does NOT exist — should be skipped.
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir+"/xdg-does-not-exist")

	t.Run("explicit override wins", func(t *testing.T) {
		t.Setenv("FORGE_PROXY_ENV_FILE", override)
		got := defaultEnvFilePath()
		if got != override {
			t.Errorf("got %q, want %q", got, override)
		}
	})

	t.Run("nonexistent override is skipped", func(t *testing.T) {
		t.Setenv("FORGE_PROXY_ENV_FILE", "/path/that/does/not/exist")
		// /etc/forge-proxy.env is the next candidate; the test can't
		// rely on it existing on the runner. The acceptable answer is
		// either /etc/forge-proxy.env (if the runner happens to have
		// one) or "". Both are correct — assert one of them.
		got := defaultEnvFilePath()
		if got != "" && got != "/etc/forge-proxy.env" {
			t.Errorf("unexpected resolved path: %q", got)
		}
	})

	t.Run("XDG_CONFIG_HOME candidate", func(t *testing.T) {
		xdg := dir + "/xdg-config"
		if err := os.MkdirAll(xdg, 0o700); err != nil {
			t.Fatalf("mkdir xdg: %v", err)
		}
		path := xdg + "/forge-proxy.env"
		if err := os.WriteFile(path, []byte("Y=1\n"), 0o600); err != nil {
			t.Fatalf("write xdg env: %v", err)
		}
		t.Setenv("FORGE_PROXY_ENV_FILE", "/path/that/does/not/exist")
		t.Setenv("XDG_CONFIG_HOME", xdg)
		got := defaultEnvFilePath()
		// /etc/forge-proxy.env, if present on the runner, would win
		// over XDG. Accept either.
		if got != path && got != "/etc/forge-proxy.env" {
			t.Errorf("expected XDG path %q (or /etc/forge-proxy.env), got %q", path, got)
		}
	})

	t.Run("no candidates exist", func(t *testing.T) {
		t.Setenv("FORGE_PROXY_ENV_FILE", "")
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", dir+"/no-such-home")
		// CWD candidate ./forge-proxy.env may exist if a previous test
		// chdir'd somewhere unusual; chdir back to the temp dir to make
		// the result deterministic.
		oldCwd, _ := os.Getwd()
		_ = os.Chdir(dir)
		defer os.Chdir(oldCwd)
		got := defaultEnvFilePath()
		// /etc/forge-proxy.env may exist on dev machines; accept either.
		if got != "" && got != "/etc/forge-proxy.env" {
			t.Errorf("expected no candidate found, got %q", got)
		}
	})
}

// TestEnvFileLoading_EndToEnd writes a temp env file, calls godotenv.Load
// the same way main() does, and asserts the values land in os.Getenv.
// Pins the contract that the bare `forge-proxy --env-file <path>` UX
// actually populates the environment the rest of the binary reads from.
func TestEnvFileLoading_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/forge.env"
	contents := []byte(strings.Join([]string{
		"# comment line — should be ignored",
		"FORGE_TEST_BASE=forgeutah.tech",
		"FORGE_TEST_QUOTED=\"value with spaces\"",
		"",
		"FORGE_TEST_EMPTY=",
	}, "\n"))
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	// Pre-set FORGE_TEST_BASE in the process environment. godotenv.Load
	// (the non-override variant) MUST leave it as-is — matches main()'s
	// "shell beats file" precedence. Other keys (FORGE_TEST_QUOTED,
	// FORGE_TEST_EMPTY) are intentionally not pre-set so we can verify
	// the file actually loads them.
	t.Setenv("FORGE_TEST_BASE", "shell-wins.example")

	if err := godotenv.Load(path); err != nil {
		t.Fatalf("godotenv.Load: %v", err)
	}

	if got := os.Getenv("FORGE_TEST_BASE"); got != "shell-wins.example" {
		t.Errorf("FORGE_TEST_BASE = %q, want shell value to win", got)
	}
	if got := os.Getenv("FORGE_TEST_QUOTED"); got != "value with spaces" {
		t.Errorf("FORGE_TEST_QUOTED = %q, want quoted value loaded from file", got)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
