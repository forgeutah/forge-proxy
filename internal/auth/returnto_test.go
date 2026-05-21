package auth

import (
	"errors"
	"testing"
)

func TestValidate_AttackMatrix(t *testing.T) {
	const base = "forgeutah.tech"
	cases := []struct {
		name      string
		input     string
		want      string // expected returned string; only set when wantErr is nil
		wantErr   bool
		notReason string // human-readable label for failure context
	}{
		// Reject cases — open-redirect attack shapes.
		{name: "external_host", input: "https://evil.com/foo", wantErr: true, notReason: "host not under forgeutah.tech"},
		{name: "protocol_relative", input: "//evil.com/foo", wantErr: true, notReason: "protocol-relative not allowed"},
		{name: "userinfo_attack", input: "https://attacker@deuce.forgeutah.tech/", wantErr: true, notReason: "userinfo forbidden"},
		{name: "port_attack", input: "https://deuce.forgeutah.tech:1234/", wantErr: true, notReason: "non-443 port forbidden"},
		{name: "idn_homograph", input: "https://xn--frgeutah-q9a.example/foo", wantErr: true, notReason: "punycode hostname"},
		{name: "idn_homograph_subdomain", input: "https://xn--evil-7za.forgeutah.tech/foo", wantErr: true, notReason: "punycode subdomain"},
		{name: "suffix_attack", input: "https://forgeutah.tech.evil.com/foo", wantErr: true, notReason: "suffix-match attack"},
		{name: "lookalike_attack", input: "https://notforgeutah.tech/foo", wantErr: true, notReason: "suffix without leading dot"},
		{name: "http_scheme", input: "http://deuce.forgeutah.tech/foo", wantErr: true, notReason: "http not https"},
		{name: "javascript_scheme", input: "javascript:alert(1)", wantErr: true, notReason: "non-https"},
		{name: "empty", input: "", wantErr: true, notReason: "empty input"},
		{name: "newline_smuggle", input: "https://deuce.forgeutah.tech/foo\nSet-Cookie: x=y", wantErr: true, notReason: "control characters"},
		{name: "tab_smuggle", input: "https://deuce.forgeutah.tech/foo\tbar", wantErr: true, notReason: "control characters"},
		// Accept cases — preserved through u.String() round-trip.
		{name: "apex_root", input: "https://forgeutah.tech/", want: "https://forgeutah.tech/"},
		{name: "subdomain_with_path", input: "https://deuce.forgeutah.tech/dashboard", want: "https://deuce.forgeutah.tech/dashboard"},
		{name: "query_and_fragment", input: "https://deuce.forgeutah.tech/dashboard?x=1#y", want: "https://deuce.forgeutah.tech/dashboard?x=1#y"},
		{name: "explicit_443", input: "https://deuce.forgeutah.tech:443/foo", want: "https://deuce.forgeutah.tech:443/foo"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Validate(tc.input, base)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate(%q) = %q, nil; want error (%s)", tc.input, got, tc.notReason)
				}
				if !errors.Is(err, ErrInvalidReturnTo) {
					t.Fatalf("Validate(%q) error = %v; want ErrInvalidReturnTo", tc.input, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q) returned unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("Validate(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidate_EmptyBaseDomain(t *testing.T) {
	// A misconfigured caller with no base domain must not accept anything.
	if _, err := Validate("https://forgeutah.tech/", ""); !errors.Is(err, ErrInvalidReturnTo) {
		t.Fatalf("Validate with empty base = %v; want ErrInvalidReturnTo", err)
	}
}
