package main

// ============================================================================
//                           CleanIP — Benchmarks
// ============================================================================
//
// Run with:
//
//     go test -bench=. -benchmem -run=^$
//     go test -bench=BenchmarkParseConfig -benchmem
//
// Results are printed with ns/op, B/op, and allocs/op.
// ============================================================================

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func BenchmarkParseConfig(b *testing.B) {
	vmessURI := "vmess://eyJ2IjoiMiIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoidXVpZCIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0="
	benches := []struct {
		name  string
		input string
	}{
		{"vless", "vless://uuid@example.com:443?type=ws&security=tls&sni=example.com"},
		{"trojan", "trojan://pass@example.com:443?sni=example.com"},
		{"ss_sip002", "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443"},
		{"vmess", vmessURI},
	}
	for _, bm := range benches {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := parseConfig(bm.input)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReplaceConfig(b *testing.B) {
	benches := []struct {
		name  string
		input string
	}{
		{"vless", "vless://uuid@example.com:443?type=ws&security=tls&sni=x.com"},
		{"trojan", "trojan://pass@example.com:443?sni=x.com"},
		{"ss", "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443"},
		{
			"vmess",
			"vmess://eyJ2IjoiMiIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoidXVpZCIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=",
		},
	}
	for _, bm := range benches {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := replaceConfig(bm.input, "1.2.3.4", 8443, "")
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSampleRange(b *testing.B) {
	benches := []struct {
		name  string
		cidr  string
		count int
	}{
		{"IPv4_/20_50", "173.245.48.0/20", 50},
		{"IPv4_/20_200", "173.245.48.0/20", 200},
		{"IPv6_/32_50", "2400:cb00::/32", 50},
	}
	for _, bm := range benches {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = sampleRange(bm.cidr, bm.count)
			}
		})
	}
}

func BenchmarkParseQueryParams(b *testing.B) {
	input := "type=ws&security=tls&sni=example.com&path=%2Ftest&host=example.com&alpn=h2%2Chttp%2F1.1&fp=chrome"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseQueryParams(input)
	}
}

func BenchmarkB64Decode(b *testing.B) {
	// A typical vmess payload (~200 bytes).
	raw := []byte(`{"v":"2","ps":"Benchmark","add":"example.com","port":"443","id":"04621bae-ab36-11ec-b909-0242ac120002","aid":"0","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls"}`)
	encoded := base64.StdEncoding.EncodeToString(raw)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := b64Decode(encoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJoinConfigLines(b *testing.B) {
	// 20 configs concatenated.
	var input string
	for i := 0; i < 20; i++ {
		input += fmt.Sprintf("vless://uuid%d@example.com:443?type=ws&security=tls&sni=x.com\n", i)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = joinConfigLines(input)
	}
}

func BenchmarkCalculateScore(b *testing.B) {
	tunnel := 250.0
	success := true
	r := QualityResult{
		LatencyAvg:    150,
		Jitter:        15,
		PacketLoss:    0.5,
		SpeedMbps:     25.3,
		TunnelLatency: &tunnel,
		XraySuccess:   &success,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = calculateScore(r)
	}
}
