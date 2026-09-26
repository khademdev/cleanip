package main

// ============================================================================
//                        CleanIP — Unit Test Suite
// ============================================================================
//
// This file is organized into four tiers:
//
//   Tier 1 — Pure helpers       (no network, no globals)
//   Tier 2 — Parsers            (config URI/JSON parsing)
//   Tier 3 — Export formatters  (Clash, sing-box)
//   Tier 4 — Concurrency        (with -race)
//
// Naming: Test<Func>_<Case>  for exact match, t.Run for table rows.
//
// All tests are hermetic: no network, no filesystem, no subprocess.
// ============================================================================

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// ============================================================================
//                              TEST HELPERS
// ============================================================================

// assertEqual fails the test if got != want. Comparable only.
func assertEqual[T comparable](t *testing.T, name string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", name, got, want)
	}
}

// assertNoError fails hard if err is non-nil.
func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// assertError ensures an error is returned.
func assertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// assertContains fails if needle is not in haystack.
func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected %q to contain %q", haystack, needle)
	}
}

// assertNotContains fails if needle IS in haystack.
func assertNotContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("expected %q to NOT contain %q", haystack, needle)
	}
}

// mustVmess builds a valid vmess:// URI from a JSON map. Fails on error.
func mustVmess(t *testing.T, obj map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal vmess obj: %v", err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(data)
}

// decodeVmess unmarshals a vmess:// URI back to its map. Fails on error.
func decodeVmess(t *testing.T, uri string) map[string]interface{} {
	t.Helper()
	body := strings.TrimPrefix(uri, "vmess://")
	data, err := b64Decode(body)
	if err != nil {
		t.Fatalf("b64Decode: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return obj
}

// sampleVmess returns a canonical vmess:// URI used by many tests.
func sampleVmess(t *testing.T) string {
	t.Helper()
	return mustVmess(t, map[string]interface{}{
		"v": "2", "ps": "Sample",
		"add": "example.com", "port": "443",
		"id":  "04621bae-ab36-11ec-b909-0242ac120002",
		"aid": "0", "net": "ws", "tls": "tls",
		"host": "example.com", "path": "/ws",
	})
}

// assertEqualFloat compares an interface{} value (typically the result
// of a JSON unmarshal into map[string]interface{}) with a float64.
//
// Why this exists: Go's type system treats interface{} and float64 as
// distinct types even when the underlying value is float64. This means
// assertEqual[T comparable] cannot be used directly with a JSON value
// like `vnext["port"]` and a literal `float64(8443)`.
//
// This helper performs the type assertion safely (no panic) and
// produces a clear error message when the underlying type is wrong.
func assertEqualFloat(t *testing.T, name string, got interface{}, want float64) {
	t.Helper()
	gotF, ok := got.(float64)
	if !ok {
		t.Errorf("%s: expected float64, got %T (%v)", name, got, got)
		return
	}
	if gotF != want {
		t.Errorf("%s: got %v, want %v", name, gotF, want)
	}
}

// ============================================================================
// TIER 1 — PURE HELPERS
// ============================================================================

// ----------------------------------------------------------------------------
// roundTo
// ----------------------------------------------------------------------------

func TestRoundTo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		value    float64
		decimals int
		want     float64
	}{
		{"zero decimals", 3.7, 0, 4.0},
		{"one decimal down", 3.44, 1, 3.4},
		{"one decimal up", 3.45, 1, 3.5},
		{"two decimals", 3.14159, 2, 3.14},
		{"negative value", -3.14, 1, -3.1},
		{"NaN returns zero", nan(), 2, 0},
		{"+Inf returns zero", posInf(), 2, 0},
		{"-Inf returns zero", negInf(), 2, 0},
		{"integer stays integer", 42, 2, 42},
		{"large value", 123456.789, 1, 123456.8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := roundTo(tc.value, tc.decimals)
			if got != tc.want {
				t.Errorf("roundTo(%v, %d) = %v, want %v",
					tc.value, tc.decimals, got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// clamp
// ----------------------------------------------------------------------------

func TestClamp(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		v, min, max, want float64
	}{
		{"below range", -5, 0, 10, 0},
		{"above range", 15, 0, 10, 10},
		{"inside range", 5, 0, 10, 5},
		{"at min", 0, 0, 10, 0},
		{"at max", 10, 0, 10, 10},
		{"fractional", 0.55, 0.0, 1.0, 0.55},
		{"negative min", -5, -10, -1, -5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := clamp(tc.v, tc.min, tc.max)
			assertEqual(t, "clamp", got, tc.want)
		})
	}
}

// ----------------------------------------------------------------------------
// formatAddr
// ----------------------------------------------------------------------------

func TestFormatAddr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ip   string
		port int
		want string
	}{
		{"IPv4", "1.2.3.4", 443, "1.2.3.4:443"},
		{"IPv6", "2001:db8::1", 443, "[2001:db8::1]:443"},
		{"IPv6 loopback", "::1", 8080, "[::1]:8080"},
		{"IPv6 full", "2001:0db8:0000:0000:0000:0000:0000:0001", 80, "[2001:0db8:0000:0000:0000:0000:0000:0001]:80"},
		{"port 1", "0.0.0.0", 1, "0.0.0.0:1"},
		{"port 65535", "0.0.0.0", 65535, "0.0.0.0:65535"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := formatAddr(tc.ip, tc.port)
			assertEqual(t, "formatAddr", got, tc.want)
		})
	}
}

// ----------------------------------------------------------------------------
// calculateJitterStdDev
// ----------------------------------------------------------------------------

func TestCalculateJitterStdDev(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		latencies []float64
		want      float64
		epsilon   float64
	}{
		{"empty", nil, 0, 0},
		{"single value", []float64{100}, 0, 0},
		{"two identical", []float64{100, 100}, 0, 0.001},
		{"two values", []float64{100, 200}, 50, 0.001},
		{"constant stream", []float64{50, 50, 50, 50, 50}, 0, 0.001},
		{"small jitter", []float64{100, 105, 95, 100}, 3.535, 0.01},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := calculateJitterStdDev(tc.latencies)
			diff := got - tc.want
			if diff < 0 {
				diff = -diff
			}
			if diff > tc.epsilon {
				t.Errorf("calculateJitterStdDev(%v) = %v, want %v (±%v)",
					tc.latencies, got, tc.want, tc.epsilon)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// mustParseTime
// ----------------------------------------------------------------------------

func TestMustParseTime(t *testing.T) {
	t.Parallel()

	t.Run("valid RFC3339", func(t *testing.T) {
		t.Parallel()
		got := mustParseTime("2026-01-15T10:30:00Z")
		if got.IsZero() {
			t.Fatal("expected non-zero time")
		}
		assertEqual(t, "year", got.Year(), 2026)
	})

	t.Run("invalid returns zero", func(t *testing.T) {
		t.Parallel()
		got := mustParseTime("not-a-timestamp")
		if !got.IsZero() {
			t.Errorf("expected zero time, got %v", got)
		}
	})

	t.Run("empty returns zero", func(t *testing.T) {
		t.Parallel()
		got := mustParseTime("")
		if !got.IsZero() {
			t.Errorf("expected zero time, got %v", got)
		}
	})
}

// ============================================================================
// b64Decode
// ============================================================================

func TestB64Decode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"standard with padding", "aGVsbG8=", "hello", false},
		{"standard no padding needed", "aGVsbG8", "hello", false},
		{"URL-safe dash", "a-b_c", "a\xfb\xbf\xc0", false},
		{"URL-safe underscore", "Pz8_Pg", "???>", false},
		{"empty", "", "", false},
		{"single char (invalid)", "A", "", true},
		{"three chars padded", "aGk", "hi", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := b64Decode(tc.input)
			if tc.wantErr {
				assertError(t, err)
				return
			}
			assertNoError(t, err)
			assertEqual(t, "decoded", string(got), tc.want)
		})
	}
}

// ============================================================================
// parseQueryParams
// ============================================================================

func TestParseQueryParams(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "simple key=value pairs",
			input: "a=1&b=2&c=3",
			want:  map[string]string{"a": "1", "b": "2", "c": "3"},
		},
		{
			name:  "URL encoded values",
			input: "path=%2Ftest%2Fsub&sni=example.com",
			want:  map[string]string{"path": "/test/sub", "sni": "example.com"},
		},
		{
			name:  "plus decodes to space",
			input: "name=hello+world",
			want:  map[string]string{"name": "hello world"},
		},
		{
			name:  "empty value",
			input: "a=1&b=&c=3",
			want:  map[string]string{"a": "1", "b": "", "c": "3"},
		},
		{
			name:  "flag without value",
			input: "a=1&flag&c=3",
			want:  map[string]string{"a": "1", "flag": "", "c": "3"},
		},
		{
			name:  "empty string",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "percent encoded",
			input: "password=p%40ssw0rd",
			want:  map[string]string{"password": "p@ssw0rd"},
		},
		{
			name:  "duplicate key takes last",
			input: "a=1&a=2",
			want:  map[string]string{"a": "2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseQueryParams(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d keys, want %d: %v",
					len(got), len(tc.want), got)
			}
			for k, v := range tc.want {
				assertEqual(t, "key "+k, got[k], v)
			}
		})
	}
}

// ============================================================================
// TIER 2 — PARSERS
// ============================================================================

// ----------------------------------------------------------------------------
// parseConfig
// ----------------------------------------------------------------------------

func TestParseConfig(t *testing.T) {
	t.Parallel()

	vmessURI := sampleVmess(t)

	cases := []struct {
		name      string
		input     string
		wantProto string
		wantAddr  string
		wantPort  int
		wantErr   bool
	}{
		// ---- VLESS ----
		{
			name:      "vless minimal",
			input:     "vless://uuid@example.com:443",
			wantProto: "vless", wantAddr: "example.com", wantPort: 443,
		},
		{
			name:      "vless with query and fragment",
			input:     "vless://uuid@example.com:443?type=ws&security=tls&sni=example.com#Test",
			wantProto: "vless", wantAddr: "example.com", wantPort: 443,
		},
		{
			name:      "vless IPv6 host",
			input:     "vless://uuid@[2001:db8::1]:443?type=ws",
			wantProto: "vless", wantAddr: "2001:db8::1", wantPort: 443,
		},
		{
			name:      "vless with reality params",
			input:     "vless://uuid@1.2.3.4:443?type=tcp&security=reality&pbk=xxx&sid=yy&sni=cloudflare.com",
			wantProto: "vless", wantAddr: "1.2.3.4", wantPort: 443,
		},
		// ---- Trojan ----
		{
			name:      "trojan minimal",
			input:     "trojan://password@example.com:443",
			wantProto: "trojan", wantAddr: "example.com", wantPort: 443,
		},
		{
			name:      "trojan with url-encoded password",
			input:     "trojan://pass%40word@example.com:8443?sni=example.com#Test",
			wantProto: "trojan", wantAddr: "example.com", wantPort: 8443,
		},
		{
			name:      "trojan IPv6",
			input:     "trojan://pass@[::1]:443",
			wantProto: "trojan", wantAddr: "::1", wantPort: 443,
		},
		// ---- Shadowsocks ----
		{
			name:      "ss with plain userinfo and @",
			input:     "ss://aes-256-gcm:password@example.com:443",
			wantProto: "ss", wantAddr: "example.com", wantPort: 443,
		},
		{
			name:      "ss SIP002 (base64 userinfo)",
			input:     "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:password")) + "@example.com:443",
			wantProto: "ss", wantAddr: "example.com", wantPort: 443,
		},
		{
			name:      "ss full base64 SIP002",
			input:     "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:password@example.com:443")),
			wantProto: "ss", wantAddr: "example.com", wantPort: 443,
		},
		// ---- VMess ----
		{
			name:      "vmess valid",
			input:     vmessURI,
			wantProto: "vmess", wantAddr: "example.com", wantPort: 443,
		},
		{
			name:      "vmess numeric port",
			input:     mustVmess(t, map[string]interface{}{"v": "2", "add": "1.2.3.4", "port": float64(8443), "id": "uuid"}),
			wantProto: "vmess", wantAddr: "1.2.3.4", wantPort: 8443,
		},
		// ---- Errors ----
		{"empty", "", "", "", 0, true},
		{"whitespace only", "   \n\t  ", "", "", 0, true},
		{"unsupported scheme", "http://example.com", "", "", 0, true},
		{"vless no @", "vless://justuuid:443", "", "", 0, true},
		{"vless invalid port", "vless://uuid@example.com:99999", "", "", 0, true},
		{"vless zero port", "vless://uuid@example.com:0", "", "", 0, true},
		{"vless missing port", "vless://uuid@example.com", "", "", 0, true},
		{"vmess bad base64", "vmess://!!!!", "", "", 0, true},
		{"ss invalid base64", "ss://!!!!", "", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseConfig(tc.input)
			if tc.wantErr {
				assertError(t, err)
				return
			}
			assertNoError(t, err)
			assertEqual(t, "proto", got.Proto, tc.wantProto)
			assertEqual(t, "addr", got.Addr, tc.wantAddr)
			assertEqual(t, "port", got.Port, tc.wantPort)
			assertEqual(t, "raw", got.Raw, tc.input)
		})
	}
}

// ----------------------------------------------------------------------------
// replaceConfig — round-trip
// ----------------------------------------------------------------------------

func TestReplaceConfig(t *testing.T) {
	t.Parallel()

	const (
		newIP   = "1.2.3.4"
		newPort = 8443
	)

	t.Run("vless round-trip", func(t *testing.T) {
		t.Parallel()
		orig := "vless://uuid@old.com:443?type=ws&security=tls&sni=old-sni.com&path=/p#Frag"
		got, err := replaceConfig(orig, newIP, newPort, "")
		assertNoError(t, err)

		assertContains(t, got, newIP)
		assertContains(t, got, ":8443")
		assertContains(t, got, "sni=old-sni.com") // SNI preserved
		assertContains(t, got, "#Frag")           // fragment preserved
		assertNotContains(t, got, "old.com")

		p, err := parseConfig(got)
		assertNoError(t, err)
		assertEqual(t, "addr", p.Addr, newIP)
		assertEqual(t, "port", p.Port, newPort)
	})

	t.Run("vless IPv6 new host gets bracketed", func(t *testing.T) {
		t.Parallel()
		orig := "vless://uuid@old.com:443?type=ws"
		got, err := replaceConfig(orig, "2001:db8::1", 443, "")
		assertNoError(t, err)
		assertContains(t, got, "[2001:db8::1]")
	})

	t.Run("trojan round-trip preserves password", func(t *testing.T) {
		t.Parallel()
		// Passwords containing "@" MUST be URL-encoded as %40 in the
		// userinfo section — otherwise the parser can't tell where the
		// password ends and the host begins. This is the standard
		// trojan:// URI convention.
		orig := "trojan://p%40ssw0rd@old.com:443?sni=example.com#MyTrojan"
		got, err := replaceConfig(orig, newIP, newPort, "")
		assertNoError(t, err)

		assertContains(t, got, "p%40ssw0rd")
		assertContains(t, got, "#MyTrojan")

		p, err := parseConfig(got)
		assertNoError(t, err)
		assertEqual(t, "addr", p.Addr, newIP)
		assertEqual(t, "port", p.Port, newPort)
	})

	t.Run("ss SIP002 round-trip", func(t *testing.T) {
		t.Parallel()
		orig := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@old.com:443#MySS"
		got, err := replaceConfig(orig, newIP, newPort, "")
		assertNoError(t, err)
		assertContains(t, got, "#MySS")

		p, err := parseConfig(got)
		assertNoError(t, err)
		assertEqual(t, "addr", p.Addr, newIP)
		assertEqual(t, "port", p.Port, newPort)
	})

	t.Run("ss full base64 round-trip", func(t *testing.T) {
		t.Parallel()
		orig := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw@old.com:443")) + "#MySS"
		got, err := replaceConfig(orig, newIP, newPort, "")
		assertNoError(t, err)

		p, err := parseConfig(got)
		assertNoError(t, err)
		assertEqual(t, "addr", p.Addr, newIP)
		assertEqual(t, "port", p.Port, newPort)
	})

	t.Run("vmess round-trip preserves everything", func(t *testing.T) {
		t.Parallel()
		orig := sampleVmess(t)
		got, err := replaceConfig(orig, newIP, newPort, "")
		assertNoError(t, err)

		obj := decodeVmess(t, got)
		assertEqual(t, "add", obj["add"], newIP)

		// port can be string or number depending on encoding roundtrip
		switch p := obj["port"].(type) {
		case float64:
			assertEqual(t, "port (number)", int(p), newPort)
		case string:
			assertEqual(t, "port (string)", p, "8443")
		default:
			t.Errorf("port has unexpected type: %T", obj["port"])
		}

		// unrelated fields preserved
		assertEqual(t, "id", obj["id"], "04621bae-ab36-11ec-b909-0242ac120002")
		assertEqual(t, "net", obj["net"], "ws")
		assertEqual(t, "tls", obj["tls"], "tls")
		assertEqual(t, "path", obj["path"], "/ws")
	})

	t.Run("unsupported scheme errors", func(t *testing.T) {
		t.Parallel()
		_, err := replaceConfig("http://example.com", newIP, newPort, "")
		assertError(t, err)
	})
}

// ----------------------------------------------------------------------------
// sampleRange
// ----------------------------------------------------------------------------

func TestSampleRange(t *testing.T) {
	t.Parallel()

	t.Run("IPv4 /20 produces valid unique in-range IPs", func(t *testing.T) {
		t.Parallel()
		const cidr = "173.245.48.0/20"
		prefix, err := netip.ParsePrefix(cidr)
		assertNoError(t, err)

		ips := sampleRange(cidr, 50)
		assertEqual(t, "count", len(ips), 50)

		seen := make(map[string]bool, len(ips))
		for _, ipStr := range ips {
			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				t.Errorf("invalid IP %q: %v", ipStr, err)
				continue
			}
			if !addr.Is4() {
				t.Errorf("expected IPv4, got %s", ipStr)
			}
			if !prefix.Contains(addr) {
				t.Errorf("IP %s outside prefix %s", ipStr, cidr)
			}
			if seen[ipStr] {
				t.Errorf("duplicate IP: %s", ipStr)
			}
			seen[ipStr] = true
		}
	})

	t.Run("IPv6 /32 produces valid unique in-range IPs", func(t *testing.T) {
		t.Parallel()
		const cidr = "2400:cb00::/32"
		prefix, err := netip.ParsePrefix(cidr)
		assertNoError(t, err)

		ips := sampleRange(cidr, 20)
		assertEqual(t, "count", len(ips), 20)

		seen := make(map[string]bool, len(ips))
		for _, ipStr := range ips {
			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				t.Errorf("invalid IP %q: %v", ipStr, err)
				continue
			}
			if !addr.Is6() {
				t.Errorf("expected IPv6, got %s", ipStr)
			}
			if !prefix.Contains(addr) {
				t.Errorf("IP %s outside prefix %s", ipStr, cidr)
			}
			if seen[ipStr] {
				t.Errorf("duplicate IP: %s", ipStr)
			}
			seen[ipStr] = true
		}
	})

	t.Run("invalid CIDR returns nil", func(t *testing.T) {
		t.Parallel()
		if got := sampleRange("not-a-cidr", 5); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("/31 prefix too small", func(t *testing.T) {
		t.Parallel()
		if got := sampleRange("192.168.1.0/31", 5); got != nil {
			t.Errorf("expected nil for /31, got %v", got)
		}
	})

	t.Run("/32 prefix rejected", func(t *testing.T) {
		t.Parallel()
		if got := sampleRange("192.168.1.1/32", 5); got != nil {
			t.Errorf("expected nil for /32, got %v", got)
		}
	})

	t.Run("count larger than range is capped", func(t *testing.T) {
		t.Parallel()
		// /30 has only 2 usable hosts (offset 1, 2)
		ips := sampleRange("192.168.1.0/30", 100)
		if len(ips) > 2 {
			t.Errorf("expected at most 2 IPs, got %d", len(ips))
		}
	})

	t.Run("zero count returns nil", func(t *testing.T) {
		t.Parallel()
		ips := sampleRange("192.168.1.0/24", 0)
		if ips != nil && len(ips) > 0 {
			t.Errorf("expected nil or empty, got %v", ips)
		}
	})
}

// ----------------------------------------------------------------------------
// extractSNI
// ----------------------------------------------------------------------------

func TestExtractSNI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "vless with sni",
			input: "vless://uuid@example.com:443?type=ws&sni=target.com&path=/",
			want:  "target.com",
		},
		{
			name:  "vless peer fallback",
			input: "vless://uuid@example.com:443?type=ws&peer=peer.com",
			want:  "peer.com",
		},
		{
			name:  "vless host fallback",
			input: "vless://uuid@example.com:443?type=ws&host=host.com",
			want:  "host.com",
		},
		{
			name:  "sni priority over peer and host",
			input: "vless://uuid@example.com:443?sni=first.com&peer=second.com&host=third.com",
			want:  "first.com",
		},
		{
			name:  "peer priority over host",
			input: "vless://uuid@example.com:443?peer=second.com&host=third.com",
			want:  "second.com",
		},
		{
			name:  "trojan sni",
			input: "trojan://pass@example.com:443?sni=trojan-sni.com",
			want:  "trojan-sni.com",
		},
		{
			name:  "vmess has no query-based SNI",
			input: sampleVmess(t),
			want:  "",
		},
		{
			name:  "ss has no query-based SNI",
			input: "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443",
			want:  "",
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "vless without query",
			input: "vless://uuid@example.com:443",
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := extractSNI(tc.input)
			assertEqual(t, "sni", got, tc.want)
		})
	}
}

// ----------------------------------------------------------------------------
// calculateScore
// ----------------------------------------------------------------------------

func TestCalculateScore(t *testing.T) {
	t.Parallel()

	t.Run("perfect score clamps to 100", func(t *testing.T) {
		t.Parallel()
		tunnel := 0.0
		success := true
		r := QualityResult{
			LatencyAvg:    0,
			Jitter:        0,
			PacketLoss:    0,
			SpeedMbps:     100,
			TunnelLatency: &tunnel,
			XraySuccess:   &success,
		}
		got := calculateScore(r)
		if got > 100.01 {
			t.Errorf("score exceeded 100: %.4f", got)
		}
		if got < 99 {
			t.Errorf("expected near-perfect score, got %.2f", got)
		}
	})

	t.Run("worst case clamps to 0", func(t *testing.T) {
		t.Parallel()
		failure := false
		r := QualityResult{
			LatencyAvg:  99999,
			Jitter:      99999,
			PacketLoss:  100,
			SpeedMbps:   0,
			XraySuccess: &failure,
		}
		got := calculateScore(r)
		if got < 0 {
			t.Errorf("score below 0: %.2f", got)
		}
		if got > 15 { // mostly tunnel=0, everything else is 0 too
			t.Errorf("expected near-zero score, got %.2f", got)
		}
	})

	t.Run("always in [0, 100] across grid", func(t *testing.T) {
		t.Parallel()
		latencies := []float64{0, 50, 200, 500, 1500, 5000}
		jitters := []float64{0, 10, 100, 500}
		losses := []float64{0, 5, 50, 100}
		speeds := []float64{0, 1, 30, 100}

		for _, lat := range latencies {
			for _, jit := range jitters {
				for _, loss := range losses {
					for _, spd := range speeds {
						r := QualityResult{
							LatencyAvg: lat,
							Jitter:     jit,
							PacketLoss: loss,
							SpeedMbps:  spd,
						}
						got := calculateScore(r)
						if got < 0 || got > 100 {
							t.Errorf("out of [0,100]: lat=%v jit=%v loss=%v spd=%v → %.2f",
								lat, jit, loss, spd, got)
						}
					}
				}
			}
		}
	})

	t.Run("xray failure zeroes tunnel component", func(t *testing.T) {
		t.Parallel()
		failure := false
		success := true
		base := QualityResult{LatencyAvg: 100, Jitter: 10, PacketLoss: 0, SpeedMbps: 20}

		rSuccess := base
		rSuccess.XraySuccess = &success
		rSuccess.TunnelLatency = ptr(200.0)

		rFailure := base
		rFailure.XraySuccess = &failure

		scoreSuccess := calculateScore(rSuccess)
		scoreFailure := calculateScore(rFailure)
		if scoreFailure >= scoreSuccess {
			t.Errorf("xray failure should score lower: success=%.2f failure=%.2f",
				scoreSuccess, scoreFailure)
		}
	})
}

// ============================================================================
// joinConfigLines
// ============================================================================

func TestJoinConfigLines(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     string
		wantCount int
		wantFirst string
	}{
		{
			name:      "single line",
			input:     "vless://uuid@example.com:443",
			wantCount: 1,
			wantFirst: "vless://uuid@example.com:443",
		},
		{
			name:      "three separate lines",
			input:     "vless://a@x.com:443\nvless://b@y.com:443\ntrojan://p@z.com:443",
			wantCount: 3,
			wantFirst: "vless://a@x.com:443",
		},
		{
			name:      "empty lines ignored",
			input:     "\n\nvless://a@x.com:443\n\n\n",
			wantCount: 1,
			wantFirst: "vless://a@x.com:443",
		},
		{
			name:      "continuation appended to previous",
			input:     "vless://uuid@example.com:443?type=ws\n&path=/split\n&sni=x.com",
			wantCount: 1,
			wantFirst: "vless://uuid@example.com:443?type=ws&path=/split&sni=x.com",
		},
		{
			name:      "whitespace around lines",
			input:     "  vless://a@x.com:443  \n\ttrojan://p@z.com:443\t",
			wantCount: 2,
			wantFirst: "vless://a@x.com:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := joinConfigLines(tc.input)
			assertEqual(t, "count", len(got), tc.wantCount)
			if tc.wantCount > 0 {
				assertEqual(t, "first", got[0], tc.wantFirst)
			}
		})
	}
}

// ============================================================================
// firstTestableConfig
// ============================================================================

func TestFirstTestableConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "vless first",
			input: "vless://a@x.com:443\ntrojan://b@y.com:443",
			want:  "vless://a@x.com:443",
		},
		{
			name:  "comment lines skipped",
			input: "# comment\nvless://a@x.com:443",
			want:  "vless://a@x.com:443",
		},
		{
			name:  "vmess detected",
			input: sampleVmess(t),
			want:  sampleVmess(t),
		},
		{
			name:  "no testable config",
			input: "random text\nanother line",
			want:  "",
		},
		{
			name:  "empty",
			input: "",
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := firstTestableConfig(tc.input)
			assertEqual(t, "first", got, tc.want)
		})
	}
}

// ============================================================================
// applyCustomDomain
// ============================================================================

func TestApplyCustomDomain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		input        string
		customDomain string
		want         string
	}{
		{
			name:         "empty domain is no-op",
			input:        "myworker.workers.dev",
			customDomain: "",
			want:         "myworker.workers.dev",
		},
		{
			name:         "simple replacement",
			input:        "myworker.workers.dev",
			customDomain: "vpn.mydomain.com",
			want:         "vpn.mydomain.com",
		},
		{
			name:         "subdomain replacement",
			input:        "sub.myworker.workers.dev",
			customDomain: "vpn.mydomain.com",
			want:         "vpn.mydomain.com",
		},
		{
			name:         "no match leaves string alone",
			input:        "example.com",
			customDomain: "vpn.mydomain.com",
			want:         "example.com",
		},
		{
			name:         "case-insensitive replacement",
			input:        "MyWorker.Workers.Dev",
			customDomain: "vpn.mydomain.com",
			want:         "vpn.mydomain.com",
		},
		{
			name:         "multiple occurrences",
			input:        "a.workers.dev and b.workers.dev",
			customDomain: "vpn.example.com",
			want:         "vpn.example.com and vpn.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := applyCustomDomain(tc.input, tc.customDomain)
			assertEqual(t, "result", got, tc.want)
		})
	}
}

// ============================================================================
// TIER 3 — EXPORT FORMATTERS
// ============================================================================

// ----------------------------------------------------------------------------
// combinedToClashProxy
// ----------------------------------------------------------------------------

func TestCombinedToClashProxy(t *testing.T) {
	t.Parallel()

	t.Run("vmess produces correct type and fields", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "vmess",
			Config: sampleVmess(t),
		}
		proxy := combinedToClashProxy(0, cc)
		if proxy == nil {
			t.Fatal("nil proxy")
		}
		assertEqual(t, "type", proxy["type"], "vmess")
		assertEqual(t, "server", proxy["server"], "1.2.3.4")
		assertEqual(t, "port", proxy["port"], 443)
		assertEqual(t, "udp", proxy["udp"], true)
		assertEqual(t, "uuid", proxy["uuid"], "04621bae-ab36-11ec-b909-0242ac120002")
		assertEqual(t, "network", proxy["network"], "ws")
	})

	t.Run("trojan produces correct type and password", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "trojan",
			Config: "trojan://password123@1.2.3.4:443?sni=example.com#MyTrojan",
		}
		proxy := combinedToClashProxy(0, cc)
		if proxy == nil {
			t.Fatal("nil proxy")
		}
		assertEqual(t, "type", proxy["type"], "trojan")
		assertEqual(t, "password", proxy["password"], "password123")
		assertEqual(t, "name (fragment)", proxy["name"], "MyTrojan")
		assertEqual(t, "sni", proxy["sni"], "example.com")
	})

	t.Run("ss produces correct cipher and password", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "ss",
			Config: "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:443#MySS",
		}
		proxy := combinedToClashProxy(0, cc)
		if proxy == nil {
			t.Fatal("nil proxy")
		}
		assertEqual(t, "type", proxy["type"], "ss")
		assertEqual(t, "cipher", proxy["cipher"], "aes-256-gcm")
		assertEqual(t, "password", proxy["password"], "password")
	})

	t.Run("vless with TLS includes servername", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "vless",
			Config: "vless://uuid@1.2.3.4:443?type=ws&security=tls&sni=cloudflare.com#Name",
		}
		proxy := combinedToClashProxy(0, cc)
		if proxy == nil {
			t.Fatal("nil proxy")
		}
		assertEqual(t, "type", proxy["type"], "vless")
		assertEqual(t, "tls", proxy["tls"], true)
		assertEqual(t, "servername", proxy["servername"], "cloudflare.com")
	})

	t.Run("vless with reality includes reality-opts", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "vless",
			Config: "vless://uuid@1.2.3.4:443?type=tcp&security=reality&pbk=PUBKEY&sid=SHORTID&sni=cf.com#Name",
		}
		proxy := combinedToClashProxy(0, cc)
		if proxy == nil {
			t.Fatal("nil proxy")
		}
		reality, ok := proxy["reality-opts"].(map[string]interface{})
		if !ok {
			t.Fatalf("reality-opts missing or wrong type: %T", proxy["reality-opts"])
		}
		assertEqual(t, "public-key", reality["public-key"], "PUBKEY")
		assertEqual(t, "short-id", reality["short-id"], "SHORTID")
	})

	t.Run("invalid config returns nil", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{Config: "not-a-valid-config"}
		if proxy := combinedToClashProxy(0, cc); proxy != nil {
			t.Errorf("expected nil, got %v", proxy)
		}
	})

	t.Run("unknown protocol returns nil", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{Config: "http://example.com"}
		if proxy := combinedToClashProxy(0, cc); proxy != nil {
			t.Errorf("expected nil, got %v", proxy)
		}
	})
}

// ----------------------------------------------------------------------------
// combinedToSingboxOutbound
// ----------------------------------------------------------------------------

func TestCombinedToSingboxOutbound(t *testing.T) {
	t.Parallel()

	t.Run("vmess", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "vmess",
			Config: sampleVmess(t),
		}
		out := combinedToSingboxOutbound(0, cc)
		if out == nil {
			t.Fatal("nil outbound")
		}
		assertEqual(t, "type", out["type"], "vmess")
		assertEqual(t, "server", out["server"], "1.2.3.4")
		assertEqual(t, "server_port", out["server_port"], 443)
		assertEqual(t, "uuid", out["uuid"], "04621bae-ab36-11ec-b909-0242ac120002")
	})

	t.Run("trojan", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "trojan",
			Config: "trojan://mypass@1.2.3.4:443?sni=example.com",
		}
		out := combinedToSingboxOutbound(0, cc)
		if out == nil {
			t.Fatal("nil outbound")
		}
		assertEqual(t, "type", out["type"], "trojan")
		assertEqual(t, "password", out["password"], "mypass")
	})

	t.Run("ss uses shadowsocks type with method field", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "ss",
			Config: "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:443",
		}
		out := combinedToSingboxOutbound(0, cc)
		if out == nil {
			t.Fatal("nil outbound")
		}
		assertEqual(t, "type", out["type"], "shadowsocks")
		assertEqual(t, "method", out["method"], "aes-256-gcm")
		assertEqual(t, "password", out["password"], "password")
	})

	t.Run("vless with tls has tls block", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{
			IP: "1.2.3.4", Port: 443, Proto: "vless",
			Config: "vless://uuid@1.2.3.4:443?security=tls&sni=cf.com",
		}
		out := combinedToSingboxOutbound(0, cc)
		if out == nil {
			t.Fatal("nil outbound")
		}
		tlsBlock, ok := out["tls"].(map[string]interface{})
		if !ok {
			t.Fatalf("tls block missing: %T", out["tls"])
		}
		assertEqual(t, "tls.enabled", tlsBlock["enabled"], true)
		assertEqual(t, "tls.server_name", tlsBlock["server_name"], "cf.com")
	})

	t.Run("invalid config returns nil", func(t *testing.T) {
		t.Parallel()
		cc := CombinedConfig{Config: "garbage"}
		if out := combinedToSingboxOutbound(0, cc); out != nil {
			t.Errorf("expected nil, got %v", out)
		}
	})
}

// ============================================================================
// TIER 4 — CONCURRENCY (run with -race)
// ============================================================================

// TestTLSCacheConcurrent exercises getTLSConfig from many goroutines.
// Any data race will be reported by `go test -race`.
func TestTLSCacheConcurrent(t *testing.T) {
	const (
		goroutines = 50
		iterations = 100
	)

	// Pre-warm the cache with a variety of keys so concurrent readers
	// hit different code paths.
	clearTLSCache()

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				sni := fmt.Sprintf("host-%d.example.com", i%5)
				fp := []string{"chrome", "firefox", "safari", "ios", "android"}[i%5]
				cfg := getTLSConfig(sni, fp)
				if cfg == nil {
					t.Errorf("nil config for %s/%s", sni, fp)
					return
				}
				if cfg.ServerName != sni {
					t.Errorf("wrong SNI: got %s, want %s", cfg.ServerName, sni)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestTLSCacheClearConcurrent exercises the swap path of clearTLSCache
// under concurrent readers. This is the specific race the fix addresses.
func TestTLSCacheClearConcurrent(t *testing.T) {
	var wg sync.WaitGroup

	// Reader goroutines.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				sni := fmt.Sprintf("reader-%d.host.com", id%4)
				cfg := getTLSConfig(sni, "chrome")
				if cfg == nil {
					t.Error("nil config under concurrent clear")
					return
				}
			}
		}(i)
	}

	// Writers clearing the cache.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				clearTLSCache()
			}
		}()
	}

	wg.Wait()
}

// ============================================================================
// SMALL UTILITIES USED BY TESTS
// ============================================================================

func nan() float64      { var x float64; return x / x }
func posInf() float64   { var x float64 = 1; return x / 0 }
func negInf() float64   { var x float64 = -1; return x / 0 }
func ptr[T any](v T) *T { return &v }
