package main

// ============================================================================
//                    CleanIP — Xray JSON Builder Tests
// ============================================================================
//
// These tests exercise the pure JSON-building functions used to construct
// Xray core configs. They run entirely offline — no subprocess, no network.
//
// Coverage target: buildStreamSettings, resolveFragment,
// buildOutboundsWithFragment, configToXrayJSON and the four protocol
// specific builders (vless/trojan/vmess/ss).
// ============================================================================

import (
	"encoding/json"
	"strings"
	"testing"
)

// ============================================================================
// buildStreamSettings
// ============================================================================

func TestBuildStreamSettings(t *testing.T) {
	t.Parallel()

	t.Run("default network is tcp", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("", "none", "", "", "", "", "", "", "", "", "", "", "", "")
		assertEqual(t, "network", ss["network"], "tcp")
		assertEqual(t, "security", ss["security"], "none")
	})

	t.Run("tls security has tlsSettings", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("tcp", "tls", "example.com", "", "", "", "", "chrome", "", "", "", "", "", "")
		assertEqual(t, "security", ss["security"], "tls")
		tls, ok := ss["tlsSettings"].(map[string]interface{})
		if !ok {
			t.Fatalf("tlsSettings missing: %T", ss["tlsSettings"])
		}
		assertEqual(t, "serverName", tls["serverName"], "example.com")
		assertEqual(t, "fingerprint", tls["fingerprint"], "chrome")
	})

	t.Run("tls with alpn splits comma list", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("tcp", "tls", "x.com", "", "", "", "h2,http/1.1", "", "", "", "", "", "", "")
		tls := ss["tlsSettings"].(map[string]interface{})
		alpn, ok := tls["alpn"].([]string)
		if !ok {
			t.Fatalf("alpn missing or wrong type: %T", tls["alpn"])
		}
		assertEqual(t, "alpn count", len(alpn), 2)
		assertEqual(t, "alpn[0]", alpn[0], "h2")
		assertEqual(t, "alpn[1]", alpn[1], "http/1.1")
	})

	t.Run("tls with echConfig includes echConfigList", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("tcp", "tls", "x.com", "", "", "", "", "", "ECHBLOB", "", "", "", "", "")
		tls := ss["tlsSettings"].(map[string]interface{})
		assertEqual(t, "echConfigList", tls["echConfigList"], "ECHBLOB")
	})

	t.Run("reality security has realitySettings", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("tcp", "reality", "cf.com", "", "", "", "", "chrome", "", "PUBKEY", "SID", "/", "", "")
		assertEqual(t, "security", ss["security"], "reality")
		rs, ok := ss["realitySettings"].(map[string]interface{})
		if !ok {
			t.Fatalf("realitySettings missing: %T", ss["realitySettings"])
		}
		assertEqual(t, "serverName", rs["serverName"], "cf.com")
		assertEqual(t, "publicKey", rs["publicKey"], "PUBKEY")
		assertEqual(t, "shortId", rs["shortId"], "SID")
		assertEqual(t, "spiderX", rs["spiderX"], "/")
	})

	t.Run("reality default fingerprint is chrome", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("tcp", "reality", "cf.com", "", "", "", "", "", "", "", "", "", "", "")
		rs := ss["realitySettings"].(map[string]interface{})
		assertEqual(t, "fingerprint", rs["fingerprint"], "chrome")
	})

	t.Run("reality default spiderX is /", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("tcp", "reality", "cf.com", "", "", "", "", "", "", "", "", "", "", "")
		rs := ss["realitySettings"].(map[string]interface{})
		assertEqual(t, "spiderX", rs["spiderX"], "/")
	})

	t.Run("ws transport has wsSettings", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("ws", "none", "", "/path", "host.com", "", "", "", "", "", "", "", "", "")
		ws, ok := ss["wsSettings"].(map[string]interface{})
		if !ok {
			t.Fatalf("wsSettings missing: %T", ss["wsSettings"])
		}
		assertEqual(t, "path", ws["path"], "/path")
		headers, ok := ws["headers"].(map[string]string)
		if !ok {
			t.Fatalf("headers missing: %T", ws["headers"])
		}
		assertEqual(t, "Host", headers["Host"], "host.com")
	})

	t.Run("ws default path is /", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("ws", "none", "", "", "", "", "", "", "", "", "", "", "", "")
		ws := ss["wsSettings"].(map[string]interface{})
		assertEqual(t, "path", ws["path"], "/")
	})

	t.Run("grpc transport has grpcSettings", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("grpc", "none", "", "", "", "myservice", "", "", "", "", "", "", "", "")
		gs := ss["grpcSettings"].(map[string]interface{})
		assertEqual(t, "serviceName", gs["serviceName"], "myservice")
	})

	t.Run("grpc multi mode sets multiMode", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("grpc", "none", "", "", "", "svc", "", "", "", "", "", "", "multi", "")
		gs := ss["grpcSettings"].(map[string]interface{})
		assertEqual(t, "multiMode", gs["multiMode"], true)
	})

	t.Run("h2 transport uses httpSettings", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("h2", "none", "", "/h2path", "h2host.com", "", "", "", "", "", "", "", "", "")
		hs, ok := ss["httpSettings"].(map[string]interface{})
		if !ok {
			t.Fatalf("httpSettings missing: %T", ss["httpSettings"])
		}
		assertEqual(t, "path", hs["path"], "/h2path")
		hosts, ok := hs["host"].([]string)
		if !ok {
			t.Fatalf("host wrong type: %T", hs["host"])
		}
		assertEqual(t, "host[0]", hosts[0], "h2host.com")
	})

	t.Run("xhttp transport uses xhttpSettings", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("xhttp", "none", "", "/xpath", "xhost.com", "", "", "", "", "", "", "", "stream", "")
		xs, ok := ss["xhttpSettings"].(map[string]interface{})
		if !ok {
			t.Fatalf("xhttpSettings missing: %T", ss["xhttpSettings"])
		}
		assertEqual(t, "path", xs["path"], "/xpath")
		assertEqual(t, "host", xs["host"], "xhost.com")
		assertEqual(t, "mode", xs["mode"], "stream")
	})

	t.Run("xhttp extra JSON is merged", func(t *testing.T) {
		t.Parallel()
		extra := `{"xmux":{"maxConcurrency":"16-32"}}`
		ss := buildStreamSettings("xhttp", "none", "", "/p", "h", "", "", "", "", "", "", "", "", extra)
		xs := ss["xhttpSettings"].(map[string]interface{})
		xmux, ok := xs["xmux"].(map[string]interface{})
		if !ok {
			t.Fatalf("xmux not merged: %T", xs["xmux"])
		}
		assertEqual(t, "xmux.maxConcurrency", xmux["maxConcurrency"], "16-32")
	})

	t.Run("xhttp invalid extra JSON is ignored", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("xhttp", "none", "", "/p", "h", "", "", "", "", "", "", "", "", "not json")
		xs := ss["xhttpSettings"].(map[string]interface{})
		if _, exists := xs["xmux"]; exists {
			t.Error("xmux should not exist for invalid JSON")
		}
	})

	t.Run("kcp transport", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("kcp", "none", "", "", "", "", "", "", "", "", "", "", "", "")
		if _, ok := ss["kcpSettings"]; !ok {
			t.Error("kcpSettings missing")
		}
	})

	t.Run("quic transport", func(t *testing.T) {
		t.Parallel()
		ss := buildStreamSettings("quic", "none", "", "", "", "", "", "", "", "", "", "", "", "")
		if _, ok := ss["quicSettings"]; !ok {
			t.Error("quicSettings missing")
		}
	})
}

// ============================================================================
// resolveFragment
// ============================================================================

func TestResolveFragment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		params        map[string]string
		smartFragment bool
		wantPackets   string
		wantLength    string
		wantInterval  string
	}{
		{
			name:         "explicit fragment packets",
			params:       map[string]string{"fragment": "1-3"},
			wantPackets:  "1-3",
			wantLength:   "100-200",
			wantInterval: "10-20",
		},
		{
			name:         "fragmentPackets alias",
			params:       map[string]string{"fragmentPackets": "1-3"},
			wantPackets:  "1-3",
			wantLength:   "100-200",
			wantInterval: "10-20",
		},
		{
			name:         "explicit length and interval",
			params:       map[string]string{"fragmentLength": "50-100", "fragmentInterval": "5-10"},
			wantPackets:  "tlshello",
			wantLength:   "50-100",
			wantInterval: "5-10",
		},
		{
			name:          "smart fragment enabled",
			params:        map[string]string{},
			smartFragment: true,
			wantPackets:   "tlshello",
			wantLength:    "10-40",
			wantInterval:  "5-15",
		},
		{
			name:         "no fragment",
			params:       map[string]string{},
			wantPackets:  "",
			wantLength:   "",
			wantInterval: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fp, fl, fi := resolveFragment(tc.params, tc.smartFragment)
			assertEqual(t, "packets", fp, tc.wantPackets)
			assertEqual(t, "length", fl, tc.wantLength)
			assertEqual(t, "interval", fi, tc.wantInterval)
		})
	}
}

// ============================================================================
// buildOutboundsWithFragment
// ============================================================================

func TestBuildOutboundsWithFragment(t *testing.T) {
	t.Parallel()

	t.Run("with fragment adds freedom outbound", func(t *testing.T) {
		t.Parallel()
		proxy := map[string]interface{}{"protocol": "vless"}
		obs := buildOutboundsWithFragment(proxy, "tlshello", "10-40", "5-15")

		assertEqual(t, "outbound count", len(obs), 2)
		assertEqual(t, "first tag", obs[0]["tag"], "fragment")
		assertEqual(t, "first protocol", obs[0]["protocol"], "freedom")
		assertEqual(t, "second protocol", obs[1]["protocol"], "vless")

		// proxy outbound must reference the fragment via proxySettings
		ps, ok := obs[1]["proxySettings"].(map[string]interface{})
		if !ok {
			t.Fatalf("proxySettings missing: %T", obs[1]["proxySettings"])
		}
		assertEqual(t, "proxySettings.tag", ps["tag"], "fragment")
	})

	t.Run("without fragment only proxy outbound", func(t *testing.T) {
		t.Parallel()
		proxy := map[string]interface{}{"protocol": "vless"}
		obs := buildOutboundsWithFragment(proxy, "", "", "")
		assertEqual(t, "outbound count", len(obs), 1)
		assertEqual(t, "protocol", obs[0]["protocol"], "vless")
	})

	t.Run("sockopt tcpNoDelay always set", func(t *testing.T) {
		t.Parallel()
		proxy := map[string]interface{}{"protocol": "vless"}
		obs := buildOutboundsWithFragment(proxy, "", "", "")
		sockopt, ok := obs[0]["sockopt"].(map[string]interface{})
		if !ok {
			t.Fatalf("sockopt missing: %T", obs[0]["sockopt"])
		}
		assertEqual(t, "tcpNoDelay", sockopt["tcpNoDelay"], true)
	})
}

// ============================================================================
// vlessToXrayJSON
// ============================================================================

func TestVlessToXrayJSON(t *testing.T) {
	t.Parallel()

	t.Run("minimal vless", func(t *testing.T) {
		t.Parallel()
		uri := "vless://04621bae-ab36-11ec-b909-0242ac120002@example.com:443"
		out, err := vlessToXrayJSON(uri, "1.2.3.4", 8443, 12345, false, "", "")
		assertNoError(t, err)
		assertValidJSON(t, out)

		cfg := parseJSON(t, out)
		outbounds := cfg["outbounds"].([]interface{})
		// only proxy outbound (no fragment)
		proxy := outbounds[0].(map[string]interface{})
		assertEqual(t, "protocol", proxy["protocol"], "vless")

		settings := proxy["settings"].(map[string]interface{})
		vnext := settings["vnext"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "address", vnext["address"], "1.2.3.4")
		assertEqualFloat(t, "port", vnext["port"], 8443)
	})

	t.Run("vless with ws+tls", func(t *testing.T) {
		t.Parallel()
		uri := "vless://uuid@old.com:443?type=ws&security=tls&sni=example.com&path=/ws&host=example.com"
		out, err := vlessToXrayJSON(uri, "1.2.3.4", 443, 9999, false, "", "")
		assertNoError(t, err)
		assertValidJSON(t, out)

		cfg := parseJSON(t, out)
		proxy := cfg["outbounds"].([]interface{})[0].(map[string]interface{})
		ss := proxy["streamSettings"].(map[string]interface{})
		assertEqual(t, "network", ss["network"], "ws")
		assertEqual(t, "security", ss["security"], "tls")
	})

	t.Run("vless with smart fragment adds freedom outbound", func(t *testing.T) {
		t.Parallel()
		uri := "vless://uuid@old.com:443?type=tcp&security=tls&sni=x.com"
		out, err := vlessToXrayJSON(uri, "1.2.3.4", 443, 9999, true, "", "")
		assertNoError(t, err)

		cfg := parseJSON(t, out)
		outbounds := cfg["outbounds"].([]interface{})
		assertEqual(t, "outbound count", len(outbounds), 2)
		first := outbounds[0].(map[string]interface{})
		assertEqual(t, "first is freedom", first["protocol"], "freedom")
	})

	t.Run("vless invalid uri returns error", func(t *testing.T) {
		t.Parallel()
		_, err := vlessToXrayJSON("vless://broken", "1.2.3.4", 443, 9999, false, "", "")
		assertError(t, err)
	})
}

// ============================================================================
// trojanToXrayJSON
// ============================================================================

func TestTrojanToXrayJSON(t *testing.T) {
	t.Parallel()

	t.Run("trojan minimal", func(t *testing.T) {
		t.Parallel()
		uri := "trojan://mypassword@example.com:443"
		out, err := trojanToXrayJSON(uri, "1.2.3.4", 8443, 12345, false, "", "")
		assertNoError(t, err)
		assertValidJSON(t, out)

		cfg := parseJSON(t, out)
		proxy := cfg["outbounds"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "protocol", proxy["protocol"], "trojan")

		settings := proxy["settings"].(map[string]interface{})
		servers := settings["servers"].([]interface{})
		assertEqual(t, "server count", len(servers), 1)
		srv := servers[0].(map[string]interface{})
		assertEqual(t, "address", srv["address"], "1.2.3.4")
		assertEqualFloat(t, "port", srv["port"], 8443)
		assertEqual(t, "password", srv["password"], "mypassword")
	})

	t.Run("trojan url-encoded password", func(t *testing.T) {
		t.Parallel()
		uri := "trojan://p%40ssw0rd@example.com:443?sni=x.com"
		out, err := trojanToXrayJSON(uri, "1.2.3.4", 443, 9999, false, "", "")
		assertNoError(t, err)

		cfg := parseJSON(t, out)
		proxy := cfg["outbounds"].([]interface{})[0].(map[string]interface{})
		srv := proxy["settings"].(map[string]interface{})["servers"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "decoded password", srv["password"], "p@ssw0rd")
	})
}

// ============================================================================
// vmessToXrayJSON
// ============================================================================

func TestVmessToXrayJSON(t *testing.T) {
	t.Parallel()

	t.Run("vmess minimal", func(t *testing.T) {
		t.Parallel()
		uri := mustVmess(t, map[string]interface{}{
			"v": "2", "add": "example.com", "port": "443",
			"id": "04621bae-ab36-11ec-b909-0242ac120002", "aid": "0",
		})
		out, err := vmessToXrayJSON(uri, "1.2.3.4", 8443, 12345, false, "", "")
		assertNoError(t, err)
		assertValidJSON(t, out)

		cfg := parseJSON(t, out)
		proxy := cfg["outbounds"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "protocol", proxy["protocol"], "vmess")

		settings := proxy["settings"].(map[string]interface{})
		vnext := settings["vnext"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "address", vnext["address"], "1.2.3.4")
		assertEqualFloat(t, "port", vnext["port"], 8443)

		users := vnext["users"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "id", users["id"], "04621bae-ab36-11ec-b909-0242ac120002")
	})

	t.Run("vmess with ws+tls", func(t *testing.T) {
		t.Parallel()
		uri := mustVmess(t, map[string]interface{}{
			"v": "2", "add": "example.com", "port": "443",
			"id": "04621bae-ab36-11ec-b909-0242ac120002", "aid": "0",
			"net": "ws", "tls": "tls", "host": "example.com", "path": "/ws",
		})
		out, err := vmessToXrayJSON(uri, "1.2.3.4", 443, 9999, false, "", "")
		assertNoError(t, err)

		cfg := parseJSON(t, out)
		proxy := cfg["outbounds"].([]interface{})[0].(map[string]interface{})
		ss := proxy["streamSettings"].(map[string]interface{})
		assertEqual(t, "network", ss["network"], "ws")
		assertEqual(t, "security", ss["security"], "tls")
	})

	t.Run("vmess invalid base64", func(t *testing.T) {
		t.Parallel()
		_, err := vmessToXrayJSON("vmess://!!!", "1.2.3.4", 443, 9999, false, "", "")
		assertError(t, err)
	})
}

// ============================================================================
// ssToXrayJSON
// ============================================================================

func TestSsToXrayJSON(t *testing.T) {
	t.Parallel()

	t.Run("ss sip002 with plain userinfo", func(t *testing.T) {
		t.Parallel()
		uri := "ss://aes-256-gcm:password@example.com:443"
		out, err := ssToXrayJSON(uri, "1.2.3.4", 8443, 12345, false, "", "")
		assertNoError(t, err)
		assertValidJSON(t, out)

		cfg := parseJSON(t, out)
		proxy := cfg["outbounds"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "protocol", proxy["protocol"], "shadowsocks")

		settings := proxy["settings"].(map[string]interface{})
		srv := settings["servers"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "address", srv["address"], "1.2.3.4")
		assertEqualFloat(t, "port", srv["port"], 8443)
		assertEqual(t, "method", srv["method"], "aes-256-gcm")
		assertEqual(t, "password", srv["password"], "password")
	})

	t.Run("ss full base64 sip002", func(t *testing.T) {
		t.Parallel()
		// "aes-128-gcm:secret@example.com:8388" base64-encoded
		uri := "ss://YWVzLTEyOC1nY206c2VjcmV0QGV4YW1wbGUuY29tOjgzODg="
		out, err := ssToXrayJSON(uri, "1.2.3.4", 8443, 12345, false, "", "")
		assertNoError(t, err)

		cfg := parseJSON(t, out)
		proxy := cfg["outbounds"].([]interface{})[0].(map[string]interface{})
		srv := proxy["settings"].(map[string]interface{})["servers"].([]interface{})[0].(map[string]interface{})
		assertEqual(t, "method", srv["method"], "aes-128-gcm")
		assertEqual(t, "password", srv["password"], "secret")
	})

	t.Run("ss invalid returns error", func(t *testing.T) {
		t.Parallel()
		_, err := ssToXrayJSON("ss://!!!", "1.2.3.4", 443, 9999, false, "", "")
		assertError(t, err)
	})
}

// ============================================================================
// configToXrayJSON — protocol dispatch
// ============================================================================

func TestConfigToXrayJSON(t *testing.T) {
	t.Parallel()

	t.Run("dispatches vless", func(t *testing.T) {
		t.Parallel()
		_, err := configToXrayJSON("vless://uuid@x.com:443", "1.2.3.4", 443, 9999, false, "", "")
		assertNoError(t, err)
	})

	t.Run("dispatches trojan", func(t *testing.T) {
		t.Parallel()
		_, err := configToXrayJSON("trojan://pass@x.com:443", "1.2.3.4", 443, 9999, false, "", "")
		assertNoError(t, err)
	})

	t.Run("dispatches vmess", func(t *testing.T) {
		t.Parallel()
		uri := mustVmess(t, map[string]interface{}{"v": "2", "add": "x.com", "port": "443", "id": "uuid", "aid": "0"})
		_, err := configToXrayJSON(uri, "1.2.3.4", 443, 9999, false, "", "")
		assertNoError(t, err)
	})

	t.Run("dispatches ss", func(t *testing.T) {
		t.Parallel()
		_, err := configToXrayJSON("ss://aes-256-gcm:pw@x.com:443", "1.2.3.4", 443, 9999, false, "", "")
		assertNoError(t, err)
	})

	t.Run("unsupported protocol errors", func(t *testing.T) {
		t.Parallel()
		_, err := configToXrayJSON("http://example.com", "1.2.3.4", 443, 9999, false, "", "")
		assertError(t, err)
	})
}

// ============================================================================
// TEST HELPERS
// ============================================================================

func assertValidJSON(t *testing.T, data []byte) {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, string(data))
	}
}

func parseJSON(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return cfg
}

// silence unused warnings
var _ = strings.TrimSpace
