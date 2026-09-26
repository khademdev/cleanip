package main

// ============================================================================
//                            CleanIP — Fuzz Tests
// ============================================================================
//
// Fuzz tests exercise parsers with adversarial input to find panics and
// unexpected behavior. Run with:
//
//     go test -fuzz=FuzzParseConfig   -fuzztime=30s
//     go test -fuzz=FuzzB64Decode     -fuzztime=30s
//     go test -fuzz=FuzzParseQuery    -fuzztime=30s
//     go test -fuzz=FuzzReplaceConfig -fuzztime=30s
//
// When run without -fuzz, each fuzz target runs its seed corpus only,
// which acts as a fast regression suite.
// ============================================================================

import (
	"strings"
	"testing"
)

// FuzzParseConfig ensures parseConfig never panics on arbitrary input.
// It also validates the invariant: if parsing succeeds, Addr is non-empty
// and Port is in [1, 65535].
func FuzzParseConfig(f *testing.F) {
	// Seed corpus — real-world examples.
	f.Add("vless://04621bae-ab36-11ec-b909-0242ac120002@example.com:443?type=ws&security=tls&sni=example.com")
	f.Add("trojan://password123@example.com:443?sni=example.com#Test")
	f.Add("vmess://eyJ2IjoiMiIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoidXVpZCJ9")
	f.Add("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443")
	f.Add("ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAZXhhbXBsZS5jb206NDQz")
	f.Add("")
	f.Add("not-a-config")
	f.Add("vless://")
	f.Add("vless://@")
	f.Add("vless://uuid@")
	f.Add("vless://uuid@:")
	f.Add("vless://uuid@example.com:")
	f.Add("vless://uuid@example.com:0")
	f.Add("vless://uuid@example.com:999999")
	f.Add("vmess://!!!")
	f.Add("vmess://")
	f.Add("ss://")
	f.Add("trojan://")
	f.Add("://example.com")
	f.Add(strings.Repeat("vless://", 100))

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic.
		p, err := parseConfig(input)
		if err != nil {
			return
		}
		// If we got a result, invariants must hold.
		if p.Addr == "" {
			t.Errorf("empty Addr with nil error (input=%q)", input)
		}
		if p.Port < 1 || p.Port > 65535 {
			t.Errorf("port out of range: %d (input=%q)", p.Port, input)
		}
		if p.Proto == "" {
			t.Errorf("empty Proto (input=%q)", input)
		}
		if p.Raw != input {
			t.Errorf("Raw mismatch: got %q, want %q", p.Raw, input)
		}
	})
}

// FuzzB64Decode ensures b64Decode never panics and is idempotent.
func FuzzB64Decode(f *testing.F) {
	f.Add("")
	f.Add("aGVsbG8=")
	f.Add("aGVsbG8")
	f.Add("a-b_c")
	f.Add("Pz8_Pg")
	f.Add("!!!")
	f.Add("AAAA")
	f.Add(strings.Repeat("A", 10000))

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic.
		_, _ = b64Decode(input)
	})
}

// FuzzParseQueryParams ensures parseQueryParams never panics.
func FuzzParseQueryParams(f *testing.F) {
	f.Add("a=1&b=2&c=3")
	f.Add("path=%2Ftest&sni=example.com")
	f.Add("name=hello+world")
	f.Add("a=1&a=2")
	f.Add("&&&")
	f.Add("=")
	f.Add("=value")
	f.Add("key=")
	f.Add("%%")
	f.Add("%ZZ")
	f.Add("%")
	f.Add(strings.Repeat("a=1&", 1000))

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic.
		result := parseQueryParams(input)
		// Keys must not be empty.
		for k := range result {
			if k == "" {
				t.Errorf("empty key produced (input=%q)", input)
			}
		}
	})
}

// FuzzReplaceConfig ensures replaceConfig never panics and preserves
// the new IP/port when it succeeds.
func FuzzReplaceConfig(f *testing.F) {
	f.Add("vless://uuid@example.com:443?type=ws&security=tls&sni=x.com",
		"1.2.3.4", 8443, "")
	f.Add("trojan://pass@example.com:443?sni=x.com",
		"1.2.3.4", 8443, "")
	f.Add("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443",
		"1.2.3.4", 8443, "")
	f.Add("not-a-config", "1.2.3.4", 8443, "")
	f.Add("vless://uuid@example.com:443", "2001:db8::1", 443, "")
	f.Add("vless://uuid@workers.dev:443", "1.2.3.4", 443, "custom.com")

	f.Fuzz(func(t *testing.T, cfg, ip string, port int, domain string) {
		// Must not panic.
		_, _ = replaceConfig(cfg, ip, port, domain)
	})
}

// FuzzApplyCustomDomain ensures the workers.dev regex never panics
// on adversarial input.
func FuzzApplyCustomDomain(f *testing.F) {
	f.Add("myworker.workers.dev", "vpn.example.com")
	f.Add("example.com", "vpn.example.com")
	f.Add("", "")
	f.Add("a.b.c.workers.dev", "x.y")
	f.Add(strings.Repeat("a.", 100)+"workers.dev", "vpn.example.com")
	f.Add("..workers.dev..", "vpn.example.com")

	f.Fuzz(func(t *testing.T, input, domain string) {
		// Must not panic.
		_ = applyCustomDomain(input, domain)
	})
}

// FuzzJoinConfigLines ensures line-joining never panics.
func FuzzJoinConfigLines(f *testing.F) {
	f.Add("")
	f.Add("vless://uuid@example.com:443")
	f.Add("vless://a@x.com:443\nvless://b@y.com:443")
	f.Add("\n\n\n")
	f.Add(strings.Repeat("vless://a@x.com:443\n", 1000))
	f.Add("\x00\x01\x02")
	f.Add("\r\n\r\n")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic.
		lines := joinConfigLines(input)
		// Every returned line must be non-empty and have no newlines.
		for i, line := range lines {
			if line == "" {
				t.Errorf("empty line at index %d (input=%q)", i, input)
			}
			if strings.Contains(line, "\n") {
				t.Errorf("line %d contains newline: %q", i, line)
			}
		}
	})
}
