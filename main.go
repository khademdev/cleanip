package main

import (
	"bufio"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ==================== EMBED ====================
//
//go:embed index.html
var embeddedIndexHTML []byte

//go:embed style.css
var embeddedStyleCSS []byte

// ==================== CONSTANTS ====================
const (
	APIPort        = 8080
	TestHost       = "www.cloudflare.com"
	DefaultSamples = 100
	DefaultMaxLat  = 800.0
	DefaultTop     = 30
	MaxCandidates  = 20000
	MaxFastResults = 200
	SocksPort      = 10808
	HistoryFile    = "cleanip_history.json"
)

var defaultPorts = []int{443, 2053, 2083, 2087, 2096, 8443}

var fallbackRangesV4 = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

var fallbackRangesV6 = []string{
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
	"2c0f:f248::/32",
}

// ==================== STATE ====================
type Progress struct {
	Phase     int     `json:"phase"`
	PhaseName string  `json:"phase_name"`
	Done      int     `json:"done"`
	Total     int     `json:"total"`
	Found     int     `json:"found"`
	Elapsed   float64 `json:"elapsed"`
	Message   string  `json:"message"`
}

type HistoryEntry struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	LastTested string  `json:"last_tested"`
	Hits       int     `json:"hits"`
	AvgLatency float64 `json:"avg_latency"`
}

var (
	scanProgress atomic.Value
	scanCancel   atomic.Value

	historyMutex sync.Mutex
	historyData  = map[string]HistoryEntry{}

	defaultWorkers = func() int {
		n := runtime.NumCPU() * 200
		if n < 400 {
			return 400
		}
		if n > 2000 {
			return 2000
		}
		return n
	}()

	qualityWorkers = func() int {
		n := runtime.NumCPU() * 20
		if n < 40 {
			return 40
		}
		if n > 120 {
			return 120
		}
		return n
	}()

	sharedDialer = &net.Dialer{KeepAlive: 30 * time.Second}

	cachedRanges []string
	rangesMutex  sync.Mutex
	rng          = rand.New(rand.NewSource(time.Now().UnixNano()))
	rngMutex     sync.Mutex

	tlsConfigCache  sync.Map
	workersDevRegex = regexp.MustCompile(`(?i)[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)*\.workers\.dev`)
)

// ==================== PROGRESS & CANCEL ====================
var progressMu sync.Mutex

func setProgress(p Progress) {
	progressMu.Lock()
	scanProgress.Store(p)
	progressMu.Unlock()
}

func updateProgress(fn func(*Progress)) {
	progressMu.Lock()
	defer progressMu.Unlock()
	p := getProgress()
	fn(&p)
	scanProgress.Store(p)
}
func getProgress() Progress {
	v := scanProgress.Load()
	if v == nil {
		return Progress{}
	}
	return v.(Progress)
}

func isCancelled() bool {
	v := scanCancel.Load()
	if v == nil {
		return false
	}
	ch, ok := v.(chan struct{})
	if !ok || ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// ==================== HISTORY ====================
func loadHistory() {
	f, err := os.Open(HistoryFile)
	if err != nil {
		return
	}
	defer f.Close()
	var data map[string]HistoryEntry
	if err := json.NewDecoder(f).Decode(&data); err == nil {
		historyMutex.Lock()
		historyData = data
		historyMutex.Unlock()
	}
}

func saveHistory() {
	historyMutex.Lock()
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for k, e := range historyData {
		if e.Hits <= 0 {
			if t := mustParseTime(e.LastTested); !t.IsZero() && t.Before(cutoff) {
				delete(historyData, k)
			}
		}
	}
	data := make(map[string]HistoryEntry, len(historyData))
	for k, v := range historyData {
		data[k] = v
	}
	historyMutex.Unlock()

	f, err := os.Create(HistoryFile)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(data)
}

func updateHistory(ip string, port int, success bool, latency float64) {
	historyMutex.Lock()
	defer historyMutex.Unlock()
	key := fmt.Sprintf("%s:%d", ip, port)
	e, ok := historyData[key]
	if !ok {
		e = HistoryEntry{IP: ip, Port: port}
	}
	e.LastTested = time.Now().Format(time.RFC3339)
	if success {
		e.Hits++
		if e.AvgLatency == 0 {
			e.AvgLatency = latency
		} else {
			e.AvgLatency = e.AvgLatency*0.7 + latency*0.3
		}
	} else {
		if e.Hits > 0 {
			e.Hits--
		}
	}
	historyData[key] = e
}

// ==================== HELPERS ====================
func roundTo(v float64, decimals int) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	p := math.Pow(10, float64(decimals))
	return math.Round(v*p) / p
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	rngMutex.Lock()
	v := rng.Intn(n)
	rngMutex.Unlock()
	return v
}

func formatAddr(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + strconv.Itoa(port)
	}
	return ip + ":" + strconv.Itoa(port)
}

// calculateJitterStdDev - Jitter واقعی (انحراف معیار)
func calculateJitterStdDev(latencies []float64) float64 {
	if len(latencies) < 2 {
		return 0
	}
	sum := 0.0
	for _, l := range latencies {
		sum += l
	}
	avg := sum / float64(len(latencies))
	variance := 0.0
	for _, l := range latencies {
		d := l - avg
		variance += d * d
	}
	return math.Sqrt(variance / float64(len(latencies)))
}

// ==================== TLS CONFIG ====================
func clearTLSCache() {
	tlsConfigCache.Range(func(k, v interface{}) bool {
		tlsConfigCache.Delete(k)
		return true
	})
}

func getTLSConfig(serverName string, fps ...string) *tls.Config {
	fingerprint := "chrome"
	if len(fps) > 0 && fps[0] != "" {
		fingerprint = fps[0]
	}
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	key := serverName + "|" + fingerprint
	if v, ok := tlsConfigCache.Load(key); ok {
		return v.(*tls.Config)
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	}
	switch fingerprint {
	case "chrome":
		cfg.NextProtos = []string{"h2", "http/1.1"}
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	case "firefox":
		cfg.NextProtos = []string{"h2", "http/1.1"}
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	case "safari":
		cfg.NextProtos = []string{"h2", "http/1.1"}
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	case "ios":
		cfg.NextProtos = []string{"h2"}
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	case "android":
		cfg.NextProtos = []string{"h2", "http/1.1"}
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	default:
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	actual, _ := tlsConfigCache.LoadOrStore(key, cfg)
	return actual.(*tls.Config)
}

// ==================== RANGES ====================
func invalidateRanges() {
	rangesMutex.Lock()
	cachedRanges = nil
	rangesMutex.Unlock()
}

func fetchRanges(useIPv6 bool) []string {
	rangesMutex.Lock()
	defer rangesMutex.Unlock()
	if cachedRanges != nil {
		return cachedRanges
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	resp, err := client.Get("https://api.cloudflare.com/client/v4/ips")
	if err != nil {
		if useIPv6 {
			return append(fallbackRangesV4, fallbackRangesV6...)
		}
		return fallbackRangesV4
	}
	defer resp.Body.Close()
	var data struct {
		Result struct {
			IPv4 []string `json:"ipv4_cidrs"`
			IPv6 []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || len(data.Result.IPv4) == 0 {
		if useIPv6 {
			return append(fallbackRangesV4, fallbackRangesV6...)
		}
		return fallbackRangesV4
	}
	cachedRanges = data.Result.IPv4
	if useIPv6 && len(data.Result.IPv6) > 0 {
		cachedRanges = append(cachedRanges, data.Result.IPv6...)
	}
	return cachedRanges
}

func sampleRange(cidr string, count int) []string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil
	}
	hostBits := 0
	if prefix.Addr().Is4() {
		hostBits = 32 - prefix.Bits()
	} else {
		hostBits = 128 - prefix.Bits()
	}
	if hostBits < 2 {
		return nil
	}
	if hostBits > 30 {
		hostBits = 30
	}
	total := uint64(1) << uint(hostBits)
	if total <= 2 {
		return nil
	}
	if uint64(count) > total-2 {
		count = int(total - 2)
	}
	if count <= 0 {
		return nil
	}
	step := (total - 2) / uint64(count)
	if step < 1 {
		step = 1
	}
	base := prefix.Masked().Addr()
	result := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	for i := 0; i < count; i++ {
		offset := uint64(1) + uint64(i)*step
		if step > 1 {
			offset += uint64(randInt(int(step/4) + 1))
		}
		if offset >= total-1 {
			offset = total - 2
		}
		var ip netip.Addr
		if base.Is4() {
			b := base.As4()
			baseInt := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
			v := baseInt + uint32(offset)
			ip = netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		} else {
			b := base.As16()
			v := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
				uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
			v += offset
			ip = netip.AddrFrom16([16]byte{b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
				byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
				byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		}
		s := ip.String()
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// ==================== TEST ====================
func dialWithTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return sharedDialer.DialContext(ctx, "tcp", addr)
}

// fastTest - با retry و fingerprint
func fastTest(ip string, port int, timeout time.Duration, serverName, fingerprint string) (float64, bool) {
	addr := formatAddr(ip, port)
	for attempt := 0; attempt < 2; attempt++ {
		t0 := time.Now()
		conn, err := dialWithTimeout(addr, timeout)
		if err != nil {
			if attempt == 0 {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return 0, false
		}
		conn.SetDeadline(time.Now().Add(timeout))
		cfg := getTLSConfig(serverName, fingerprint)
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			if attempt == 0 {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return 0, false
		}
		_ = tlsConn.Close()
		return float64(time.Since(t0).Microseconds()) / 1000.0, true
	}
	return 0, false
}

func fastTestAllPorts(ip string, ports []int, timeout time.Duration, serverName string) (int, float64, bool) {
	if len(ports) == 0 {
		return 0, 0, false
	}
	if serverName == "" {
		serverName = TestHost
	}
	if len(ports) == 1 {
		if lat, ok := fastTest(ip, ports[0], timeout, serverName, "chrome"); ok {
			return ports[0], lat, true
		}
		return 0, 0, false
	}
	type pres struct {
		port int
		lat  float64
	}
	ch := make(chan pres, len(ports))
	for _, p := range ports {
		go func(port int) {
			if lat, ok := fastTest(ip, port, timeout, serverName, "chrome"); ok {
				ch <- pres{port, lat}
			} else {
				ch <- pres{0, 0}
			}
		}(p)
	}
	bestPort := 0
	bestLat := 999999.0
	for i := 0; i < len(ports); i++ {
		r := <-ch
		if r.port != 0 && r.lat < bestLat {
			bestLat = r.lat
			bestPort = r.port
		}
	}
	if bestPort == 0 {
		return 0, 0, false
	}
	return bestPort, bestLat, true
}

// ==================== THROUGHPUT (Speed Test) ====================
// measureThroughput - دانلود واقعی از speed.cloudflare.com
func measureThroughput(ip string, port int, serverName string, timeout time.Duration) float64 {
	addr := formatAddr(ip, port)
	conn, err := dialWithTimeout(addr, timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	cfg := getTLSConfig(serverName)
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return 0
	}
	defer tlsConn.Close()

	// درخواست دانلود ۱۰۰ کیلوبایت
	req := "GET /__down?bytes=100000 HTTP/1.1\r\n" +
		"Host: " + serverName + "\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	t0 := time.Now()
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return 0
	}

	br := bufio.NewReader(tlsConn)
	// رد کردن header
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0
		}
		if line == "\r\n" {
			break
		}
	}
	// خواندن body
	n, _ := io.Copy(io.Discard, br)
	elapsed := time.Since(t0).Seconds()
	if elapsed <= 0 || n <= 0 {
		return 0
	}
	mbps := (float64(n) * 8.0) / (elapsed * 1000000.0)
	return roundTo(mbps, 2)
}

// ==================== QUALITY ====================
type QualityResult struct {
	IP            string   `json:"ip"`
	Port          int      `json:"port"`
	LatencyAvg    float64  `json:"latency_avg"`
	Jitter        float64  `json:"jitter"`
	PacketLoss    float64  `json:"packet_loss"`
	Score         float64  `json:"score"`
	SpeedMbps     float64  `json:"speed_mbps"`
	TunnelLatency *float64 `json:"tunnel_latency"`
	XraySuccess   *bool    `json:"xray_success"`
	IPVersion     string   `json:"ip_version,omitempty"`
}

func measureQuality(ip string, port int, timeout time.Duration, samples int, serverName string) QualityResult {
	type sampleRes struct {
		lat float64
		ok  bool
	}
	results := make([]sampleRes, samples)
	var wg sync.WaitGroup
	maxParallel := 8
	if samples < maxParallel {
		maxParallel = samples
	}
	sem := make(chan struct{}, maxParallel)
	for i := 0; i < samples; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			if lat, ok := fastTest(ip, port, timeout, serverName, "chrome"); ok {
				results[idx] = sampleRes{lat, true}
			}
		}(i)
	}
	wg.Wait()

	latencies := make([]float64, 0, samples)
	for _, r := range results {
		if r.ok {
			latencies = append(latencies, r.lat)
		}
	}
	ver := "IPv4"
	if strings.Contains(ip, ":") {
		ver = "IPv6"
	}
	if len(latencies) == 0 {
		return QualityResult{IP: ip, Port: port, LatencyAvg: 9999, PacketLoss: 100, IPVersion: ver}
	}
	sum := 0.0
	for _, l := range latencies {
		sum += l
	}
	avg := sum / float64(len(latencies))
	loss := float64(samples-len(latencies)) / float64(samples) * 100
	return QualityResult{
		IP: ip, Port: port, LatencyAvg: avg,
		Jitter:     calculateJitterStdDev(latencies),
		PacketLoss: loss,
		IPVersion:  ver,
	}
}

func calculateScore(r QualityResult) float64 {
	latencyScore := clamp((1500-r.LatencyAvg)/1400, 0, 1)
	jitterScore := clamp((300-r.Jitter)/295, 0, 1)
	lossScore := clamp(1-r.PacketLoss/100, 0, 1)
	speedScore := 0.4
	if r.SpeedMbps > 0 {
		speedScore = clamp(r.SpeedMbps/30, 0, 1)
	}
	tunnelScore := 0.5
	if r.TunnelLatency != nil {
		tunnelScore = clamp((3000-*r.TunnelLatency)/2900, 0, 1)
	} else if r.XraySuccess != nil && !*r.XraySuccess {
		tunnelScore = 0
	}
	return (0.30*latencyScore + 0.15*jitterScore + 0.20*lossScore +
		0.25*speedScore + 0.10*tunnelScore) * 100
}

// ==================== XRAY ====================
var (
	xrayPathMutex  sync.Mutex
	xrayPathCached string
	xrayPathDone   bool
)

func findXrayBinary() string {
	xrayPathMutex.Lock()
	defer xrayPathMutex.Unlock()
	if xrayPathDone && xrayPathCached != "" {
		if info, err := os.Stat(xrayPathCached); err == nil && !info.IsDir() {
			return xrayPathCached
		}
		xrayPathDone = false
		xrayPathCached = ""
	}
	if !xrayPathDone {
		xrayPathCached = detectXrayBinary()
		xrayPathDone = true
	}
	return xrayPathCached
}

func refreshXrayPath() {
	xrayPathMutex.Lock()
	xrayPathDone = false
	xrayPathMutex.Unlock()
}

func detectXrayBinary() string {
	name := "xray"
	if runtime.GOOS == "windows" {
		name = "xray.exe"
	}
	candidates := []string{filepath.Join("xray_core", name), name, filepath.Join(".", name)}
	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Size() < 5*1024*1024 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		verCmd := exec.CommandContext(ctx, p, "version")
		hideWindow(verCmd)
		err = verCmd.Run()
		cancel()
		if err != nil {
			continue
		}
		abs, _ := filepath.Abs(p)
		return abs
	}
	return ""
}

func urlDecode(s string) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			b, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", err
			}
			sb.WriteByte(byte(b))
			i += 2
		} else if s[i] == '+' {
			sb.WriteByte(' ')
		} else {
			sb.WriteByte(s[i])
		}
	}
	return sb.String(), nil
}

func parseQueryParams(query string) map[string]string {
	params := map[string]string{}
	for _, kv := range strings.Split(query, "&") {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) == 2 {
			if v, err := urlDecode(pair[1]); err == nil {
				params[pair[0]] = v
			} else {
				params[pair[0]] = pair[1]
			}
		} else if len(pair) == 1 && pair[0] != "" {
			params[pair[0]] = ""
		}
	}
	return params
}

func buildStreamSettings(network, security, sni, path, hostHeader, serviceName, alpn, fingerprint, echConfig, publicKey, shortID, spiderX, mode, extra string) map[string]interface{} {
	if network == "" {
		network = "tcp"
	}
	ss := map[string]interface{}{"network": network}

	// ===== Security Layer =====
	switch security {
	case "tls":
		ss["security"] = "tls"
		tlsSettings := map[string]interface{}{}
		if sni != "" {
			tlsSettings["serverName"] = sni
		}
		if alpn != "" {
			tlsSettings["alpn"] = strings.Split(alpn, ",")
		}
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		tlsSettings["fingerprint"] = fingerprint
		if echConfig != "" {
			tlsSettings["echConfigList"] = echConfig
		}
		ss["tlsSettings"] = tlsSettings

	case "reality":
		ss["security"] = "reality"
		rs := map[string]interface{}{}
		if sni != "" {
			rs["serverName"] = sni
		}
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		rs["fingerprint"] = fingerprint
		if publicKey != "" {
			rs["publicKey"] = publicKey
		}
		if shortID != "" {
			rs["shortId"] = shortID
		}
		if spiderX != "" {
			rs["spiderX"] = spiderX
		} else {
			rs["spiderX"] = "/"
		}
		ss["realitySettings"] = rs

	default:
		ss["security"] = "none"
	}

	// ===== Transport Layer =====
	switch network {
	case "ws":
		ws := map[string]interface{}{}
		if path != "" {
			ws["path"] = path
		} else {
			ws["path"] = "/"
		}
		if hostHeader != "" {
			ws["headers"] = map[string]string{"Host": hostHeader}
		}
		ss["wsSettings"] = ws

	case "grpc":
		gs := map[string]interface{}{}
		if serviceName != "" {
			gs["serviceName"] = serviceName
		}
		if mode == "multi" {
			gs["multiMode"] = true
		}
		ss["grpcSettings"] = gs

	case "h2", "http":
		hs := map[string]interface{}{}
		if path != "" {
			hs["path"] = path
		}
		if hostHeader != "" {
			hs["host"] = []string{hostHeader}
		}
		ss["httpSettings"] = hs

	case "xhttp":
		xs := map[string]interface{}{}
		if path != "" {
			xs["path"] = path
		}
		if hostHeader != "" {
			xs["host"] = hostHeader
		}
		if mode != "" {
			xs["mode"] = mode
		}
		if extra != "" {
			var extraObj map[string]interface{}
			if err := json.Unmarshal([]byte(extra), &extraObj); err == nil {
				for k, v := range extraObj {
					xs[k] = v
				}
			}
		}
		ss["xhttpSettings"] = xs

	case "kcp", "mkcp":
		ss["kcpSettings"] = map[string]interface{}{}

	case "quic":
		ss["quicSettings"] = map[string]interface{}{}
	}

	return ss
}
func vlessToXrayJSON(uri, ip string, port, socksPort int, smartFragment bool, testSNI, echConfig string) ([]byte, error) {
	u := strings.TrimPrefix(uri, "vless://")
	if i := strings.Index(u, "#"); i >= 0 {
		u = u[:i]
	}
	var query string
	if i := strings.Index(u, "?"); i >= 0 {
		query = u[i+1:]
		u = u[:i]
	}
	parts := strings.SplitN(u, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid")
	}
	uuid := parts[0]
	params := parseQueryParams(query)

	sni := params["sni"]
	if sni == "" {
		sni = params["peer"]
	}
	if sni == "" {
		sni = params["host"]
	}
	if sni == "" {
		sni = TestHost
	}
	if testSNI != "" {
		sni = testSNI
	}

	network := params["type"]
	security := params["security"]
	if security == "" {
		security = "none"
	}

	ss := buildStreamSettings(
		network, security, sni,
		params["path"], params["host"], params["serviceName"],
		params["alpn"], params["fp"], echConfig,
		params["pbk"], params["sid"], params["spx"],
		params["mode"], params["extra"],
	)

	proxyOutbound := map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{"address": ip, "port": port,
					"users": []map[string]interface{}{{"id": uuid, "encryption": "none"}}},
			},
		},
		"streamSettings": ss,
	}

	fp, fl, fi := resolveFragment(params, smartFragment)
	outbounds := buildOutboundsWithFragment(proxyOutbound, fp, fl, fi)

	config := map[string]interface{}{
		"log": map[string]string{"loglevel": "none"},
		"inbounds": []map[string]interface{}{
			{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
				"settings": map[string]interface{}{"udp": false, "auth": "noauth"}},
		},
		"outbounds": outbounds,
	}
	return json.Marshal(config)
}
func trojanToXrayJSON(uri, ip string, port, socksPort int, smartFragment bool, testSNI, echConfig string) ([]byte, error) {
	u := strings.TrimPrefix(uri, "trojan://")
	if i := strings.Index(u, "#"); i >= 0 {
		u = u[:i]
	}
	var query string
	if i := strings.Index(u, "?"); i >= 0 {
		query = u[i+1:]
		u = u[:i]
	}
	at := strings.Index(u, "@")
	if at < 0 {
		return nil, fmt.Errorf("invalid")
	}
	passwordRaw := u[:at]
	uriPort := port
	password, err := urlDecode(passwordRaw)
	if err != nil {
		password = passwordRaw
	}
	params := parseQueryParams(query)

	sni := params["sni"]
	if sni == "" {
		sni = params["peer"]
	}
	if sni == "" {
		sni = params["host"]
	}
	if sni == "" {
		sni = TestHost
	}
	if testSNI != "" {
		sni = testSNI
	}

	network := params["type"]
	security := params["security"]
	if security == "" {
		security = "tls"
	}

	ss := buildStreamSettings(
		network, security, sni,
		params["path"], params["host"], params["serviceName"],
		params["alpn"], params["fp"], echConfig,
		params["pbk"], params["sid"], params["spx"],
		params["mode"], params["extra"],
	)

	proxyOutbound := map[string]interface{}{
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": ip, "port": uriPort, "password": password},
			},
		},
		"streamSettings": ss,
	}

	fp, fl, fi := resolveFragment(params, smartFragment)
	outbounds := buildOutboundsWithFragment(proxyOutbound, fp, fl, fi)

	config := map[string]interface{}{
		"log": map[string]string{"loglevel": "none"},
		"inbounds": []map[string]interface{}{
			{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
				"settings": map[string]interface{}{"udp": false, "auth": "noauth"}},
		},
		"outbounds": outbounds,
	}
	return json.Marshal(config)
}
func vmessToXrayJSON(uri, ip string, port, socksPort int, smartFragment bool, testSNI, echConfig string) ([]byte, error) {
	body := strings.TrimPrefix(uri, "vmess://")
	data, err := b64Decode(body)
	if err != nil {
		return nil, err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	uuid, _ := obj["id"].(string)
	if uuid == "" {
		return nil, fmt.Errorf("vmess: no id")
	}

	alterID := 0
	switch aid := obj["aid"].(type) {
	case float64:
		alterID = int(aid)
	case string:
		alterID, _ = strconv.Atoi(aid)
	}

	secMethod := "auto"
	if scy, ok := obj["scy"].(string); ok && scy != "" {
		secMethod = scy
	}

	network := "tcp"
	if net, ok := obj["net"].(string); ok && net != "" {
		network = net
	}

	tlsMode := ""
	if tls, ok := obj["tls"].(string); ok {
		tlsMode = tls
	}
	security := "none"
	if tlsMode == "tls" {
		security = "tls"
	}

	sni := ""
	if s, ok := obj["sni"].(string); ok && s != "" {
		sni = s
	}
	if sni == "" {
		if h, ok := obj["host"].(string); ok {
			sni = h
		}
	}
	if sni == "" {
		sni = TestHost
	}
	if testSNI != "" {
		sni = testSNI
	}

	path, _ := obj["path"].(string)
	host, _ := obj["host"].(string)
	alpn, _ := obj["alpn"].(string)
	fp, _ := obj["fp"].(string)

	serviceName, _ := obj["serviceName"].(string)
	if serviceName == "" {
		serviceName = path
	}

	mode, _ := obj["mode"].(string)
	extra := ""
	if extraObj, ok := obj["extra"].(map[string]interface{}); ok {
		if b, err := json.Marshal(extraObj); err == nil {
			extra = string(b)
		}
	}

	ss := buildStreamSettings(
		network, security, sni,
		path, host, serviceName,
		alpn, fp, echConfig,
		"", "", "",
		mode, extra,
	)

	proxyOutbound := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{"address": ip, "port": port,
					"users": []map[string]interface{}{{
						"id":       uuid,
						"alterId":  alterID,
						"security": secMethod,
					}}},
			},
		},
		"streamSettings": ss,
	}

	fp2, fl, fi := resolveFragment(map[string]string{}, smartFragment)
	outbounds := buildOutboundsWithFragment(proxyOutbound, fp2, fl, fi)

	config := map[string]interface{}{
		"log": map[string]string{"loglevel": "none"},
		"inbounds": []map[string]interface{}{
			{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
				"settings": map[string]interface{}{"udp": false, "auth": "noauth"}},
		},
		"outbounds": outbounds,
	}
	return json.Marshal(config)
}

func ssToXrayJSON(uri, ip string, port, socksPort int, smartFragment bool, testSNI, echConfig string) ([]byte, error) {
	body := strings.TrimPrefix(uri, "ss://")
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}

	var method, password string
	var uriPort int

	if at := strings.Index(body, "@"); at >= 0 {
		userinfo := body[:at]
		hostPort := body[at+1:]

		if dec, err := b64Decode(userinfo); err == nil {
			s := string(dec)
			if i := strings.Index(s, ":"); i >= 0 {
				method = s[:i]
				password = s[i+1:]
			}
		} else if i := strings.Index(userinfo, ":"); i >= 0 {
			method = userinfo[:i]
			password = userinfo[i+1:]
		}

		_, p, err := net.SplitHostPort(hostPort)
		if err != nil {
			return nil, err
		}
		uriPort, _ = strconv.Atoi(p)
	} else {
		dec, err := b64Decode(body)
		if err != nil {
			return nil, err
		}
		s := string(dec)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, fmt.Errorf("ss: no @")
		}
		userinfo := s[:at]
		hostPort := s[at+1:]
		if i := strings.Index(userinfo, ":"); i >= 0 {
			method = userinfo[:i]
			password = userinfo[i+1:]
		}
		_, p, err := net.SplitHostPort(hostPort)
		if err != nil {
			return nil, err
		}
		uriPort, _ = strconv.Atoi(p)
	}

	if method == "" {
		return nil, fmt.Errorf("ss: no method")
	}
	if uriPort == 0 {
		uriPort = port
	}

	proxyOutbound := map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": ip, "port": uriPort, "method": method, "password": password},
			},
		},
	}

	outbounds := []map[string]interface{}{proxyOutbound}

	config := map[string]interface{}{
		"log": map[string]string{"loglevel": "none"},
		"inbounds": []map[string]interface{}{
			{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
				"settings": map[string]interface{}{"udp": false, "auth": "noauth"}},
		},
		"outbounds": outbounds,
	}
	return json.Marshal(config)
}
func resolveFragment(params map[string]string, smartFragment bool) (string, string, string) {
	fragPackets := params["fragment"]
	if fragPackets == "" {
		fragPackets = params["fragmentPackets"]
	}
	fragLength := params["fragmentLength"]
	fragInterval := params["fragmentInterval"]
	if fragPackets != "" {
		if fragLength == "" {
			fragLength = "100-200"
		}
		if fragInterval == "" {
			fragInterval = "10-20"
		}
		return fragPackets, fragLength, fragInterval
	}
	if fragLength != "" || fragInterval != "" {
		if fragLength == "" {
			fragLength = "100-200"
		}
		if fragInterval == "" {
			fragInterval = "10-20"
		}
		return "tlshello", fragLength, fragInterval
	}
	if smartFragment {
		return "tlshello", "10-40", "5-15"
	}
	return "", "", ""
}

func buildOutboundsWithFragment(proxyOutbound map[string]interface{}, fp, fl, fi string) []map[string]interface{} {
	outbounds := []map[string]interface{}{}
	if fp != "" {
		fragmentOutbound := map[string]interface{}{
			"tag": "fragment", "protocol": "freedom",
			"settings": map[string]interface{}{
				"fragment":       map[string]interface{}{"packets": fp, "length": fl, "interval": fi},
				"domainStrategy": "AsIs",
			},
		}
		proxyOutbound["proxySettings"] = map[string]interface{}{"tag": "fragment"}
		outbounds = append(outbounds, fragmentOutbound)
	}
	// TCP NoDelay only (TFO can fail on some kernels)
	proxyOutbound["sockopt"] = map[string]interface{}{"tcpNoDelay": true}
	outbounds = append(outbounds, proxyOutbound)
	return outbounds
}

func configToXrayJSON(uri, ip string, port, socksPort int, smartFragment bool, testSNI, echConfig string) ([]byte, error) {
	switch {
	case strings.HasPrefix(uri, "vless://"):
		return vlessToXrayJSON(uri, ip, port, socksPort, smartFragment, testSNI, echConfig)
	case strings.HasPrefix(uri, "trojan://"):
		return trojanToXrayJSON(uri, ip, port, socksPort, smartFragment, testSNI, echConfig)
	case strings.HasPrefix(uri, "vmess://"):
		return vmessToXrayJSON(uri, ip, port, socksPort, smartFragment, testSNI, echConfig)
	case strings.HasPrefix(uri, "ss://"):
		return ssToXrayJSON(uri, ip, port, socksPort, smartFragment, testSNI, echConfig)
	}
	return nil, fmt.Errorf("unsupported protocol")
}
func testWithXray(configURI, ip string, port, socksPort int, timeout time.Duration, smartFragment bool, testSNI, echConfig string) *float64 {
	validPrefixes := []string{"vless://", "trojan://", "vmess://", "ss://"}
	valid := false
	for _, p := range validPrefixes {
		if strings.HasPrefix(configURI, p) {
			valid = true
			break
		}
	}
	if !valid {
		return nil
	}

	xrayBin := findXrayBinary()
	if xrayBin == "" {
		return nil
	}
	jsonCfg, err := configToXrayJSON(configURI, ip, port, socksPort, smartFragment, testSNI, echConfig)
	if err != nil {
		return nil
	}
	tmp, err := os.CreateTemp("", "xray-*.json")
	if err != nil {
		return nil
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(jsonCfg); err != nil {
		tmp.Close()
		return nil
	}
	tmp.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, xrayBin, "run", "-c", tmpName)
	hideWindow(cmd)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	var proxyConn net.Conn
	for time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
		proxyConn, err = dialSOCKS5(fmt.Sprintf("127.0.0.1:%d", socksPort), "speed.cloudflare.com:443", 300*time.Millisecond)
		if err == nil {
			break
		}
	}
	if proxyConn == nil {
		return nil
	}
	defer proxyConn.Close()

	tlsConn := tls.Client(proxyConn, &tls.Config{
		ServerName:         "speed.cloudflare.com",
		InsecureSkipVerify: true,
	})
	tlsConn.SetDeadline(time.Now().Add(timeout))
	t0 := time.Now()
	if err := tlsConn.Handshake(); err != nil {
		return nil
	}
	lat := float64(time.Since(t0).Microseconds()) / 1000.0
	_ = tlsConn.Close()
	return &lat
}
func dialSOCKS5(proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != 5 || buf[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting failed")
	}
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("invalid port")
	}
	req := []byte{5, 1, 0}
	parsedIP := net.ParseIP(host)
	if v4 := parsedIP.To4(); v4 != nil {
		req = append(req, 1, v4[0], v4[1], v4[2], v4[3])
	} else if v6 := parsedIP.To16(); v6 != nil {
		req = append(req, 4)
		req = append(req, v6...)
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("hostname too long")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: %d", resp[1])
	}
	switch resp[3] {
	case 1:
		_, _ = io.CopyN(io.Discard, conn, 6)
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err == nil {
			_, _ = io.CopyN(io.Discard, conn, int64(lb[0])+2)
		}
	case 4:
		_, _ = io.CopyN(io.Discard, conn, 18)
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// ==================== PARSER ====================
type CombinedConfig struct {
	IP          string  `json:"ip"`
	Port        int     `json:"port"`
	Latency     float64 `json:"latency_ms"`
	Score       float64 `json:"score"`
	PacketLoss  float64 `json:"packet_loss"`
	Jitter      float64 `json:"jitter"`
	XraySuccess *bool   `json:"xray_success"`
	Proto       string  `json:"proto"`
	Config      string  `json:"config"`
	SourceIdx   int     `json:"source_idx"`
}

type ParsedConfig struct {
	Raw, Proto, Addr string
	Port             int
}

func b64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

func parseConfig(cfg string) (ParsedConfig, error) {
	cfg = strings.TrimSpace(cfg)
	if cfg == "" {
		return ParsedConfig{}, fmt.Errorf("empty")
	}
	switch {
	case strings.HasPrefix(cfg, "vmess://"):
		return parseVmess(cfg)
	case strings.HasPrefix(cfg, "vless://"):
		return parseURI(cfg, "vless")
	case strings.HasPrefix(cfg, "trojan://"):
		return parseURI(cfg, "trojan")
	case strings.HasPrefix(cfg, "ss://"):
		return parseSS(cfg)
	}
	return ParsedConfig{}, fmt.Errorf("unsupported")
}

func parseVmess(cfg string) (ParsedConfig, error) {
	body := strings.TrimPrefix(cfg, "vmess://")
	data, err := b64Decode(body)
	if err != nil {
		return ParsedConfig{}, err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return ParsedConfig{}, err
	}
	addr, _ := obj["add"].(string)
	if addr == "" {
		return ParsedConfig{}, fmt.Errorf("no add")
	}
	port := 0
	switch p := obj["port"].(type) {
	case float64:
		port = int(p)
	case string:
		port, _ = strconv.Atoi(p)
	}
	if port <= 0 || port > 65535 {
		return ParsedConfig{}, fmt.Errorf("vmess: invalid port %d", port)
	}
	return ParsedConfig{Raw: cfg, Proto: "vmess", Addr: addr, Port: port}, nil
}

func parseURI(cfg, proto string) (ParsedConfig, error) {
	body := cfg[len(proto)+3:]
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	if i := strings.Index(body, "?"); i >= 0 {
		body = body[:i]
	}
	at := strings.Index(body, "@")
	if at < 0 {
		return ParsedConfig{}, fmt.Errorf("no @")
	}
	hostPort := body[at+1:]
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return ParsedConfig{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return ParsedConfig{}, fmt.Errorf("invalid port: %s", portStr)
	}
	return ParsedConfig{Raw: cfg, Proto: proto, Addr: host, Port: port}, nil
}

func parseSS(cfg string) (ParsedConfig, error) {
	body := strings.TrimPrefix(cfg, "ss://")
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	if at := strings.Index(body, "@"); at >= 0 {
		hostPort := body[at+1:]
		host, portStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			return ParsedConfig{}, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return ParsedConfig{}, fmt.Errorf("invalid ss port: %s", portStr)
		}
		return ParsedConfig{Raw: cfg, Proto: "ss", Addr: host, Port: port}, nil
	}
	data, err := b64Decode(body)
	if err != nil {
		return ParsedConfig{}, err
	}
	s := string(data)
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return ParsedConfig{}, fmt.Errorf("no @")
	}
	hostPort := s[at+1:]
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return ParsedConfig{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return ParsedConfig{}, fmt.Errorf("invalid ss port: %s", portStr)
	}
	return ParsedConfig{Raw: cfg, Proto: "ss", Addr: host, Port: port}, nil
}

func replaceConfig(cfg string, newIP string) (string, error) {
	cfg = strings.TrimSpace(cfg)
	switch {
	case strings.HasPrefix(cfg, "vmess://"):
		return replaceVmess(cfg, newIP)
	case strings.HasPrefix(cfg, "vless://"):
		return replaceURI(cfg, newIP)
	case strings.HasPrefix(cfg, "trojan://"):
		return replaceURI(cfg, newIP)
	case strings.HasPrefix(cfg, "ss://"):
		return replaceSS(cfg, newIP)
	}
	return "", fmt.Errorf("unsupported")
}

func replaceVmess(cfg, newIP string) (string, error) {
	body := strings.TrimPrefix(cfg, "vmess://")
	data, err := b64Decode(body)
	if err != nil {
		return "", err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return "", err
	}
	obj["add"] = newIP
	newData, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(newData), nil
}

func replaceURI(cfg, newIP string) (string, error) {
	schemeEnd := strings.Index(cfg, "://")
	if schemeEnd < 0 {
		return "", fmt.Errorf("invalid")
	}
	prefix := cfg[:schemeEnd+3]
	rest := cfg[schemeEnd+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return "", fmt.Errorf("no @")
	}
	afterAt := rest[at+1:]
	endIdx := len(afterAt)
	for i := 0; i < len(afterAt); i++ {
		c := afterAt[i]
		if c == '?' || c == '#' || c == '/' {
			endIdx = i
			break
		}
	}
	hostPort := afterAt[:endIdx]
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", err
	}
	newHost := newIP
	if strings.Contains(newIP, ":") {
		newHost = "[" + newIP + "]"
	}
	return prefix + rest[:at+1] + newHost + ":" + portStr + afterAt[endIdx:], nil
}

func replaceSS(cfg, newIP string) (string, error) {
	body := strings.TrimPrefix(cfg, "ss://")
	var fragment string
	if i := strings.Index(body, "#"); i >= 0 {
		fragment = body[i:]
		body = body[:i]
	}
	if strings.Contains(body, "@") {
		return replaceURI("ss://"+body+fragment, newIP)
	}
	data, err := b64Decode(body)
	if err != nil {
		return "", err
	}
	s := string(data)
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return "", fmt.Errorf("no @")
	}
	hostPort := s[at+1:]
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", err
	}
	newData := s[:at+1] + newIP + ":" + portStr
	return "ss://" + base64.StdEncoding.EncodeToString([]byte(newData)) + fragment, nil
}

func joinConfigLines(text string) []string {
	rawLines := strings.Split(text, "\n")
	joined := make([]string, 0)
	var cur strings.Builder
	protos := []string{"vless://", "vmess://", "trojan://", "ss://"}
	isProto := func(s string) bool {
		for _, p := range protos {
			if strings.HasPrefix(s, p) {
				return true
			}
		}
		return false
	}
	for _, line := range rawLines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if isProto(t) {
			if cur.Len() > 0 {
				joined = append(joined, cur.String())
				cur.Reset()
			}
			cur.WriteString(t)
		} else if cur.Len() > 0 {
			cur.WriteString(t)
		}
	}
	if cur.Len() > 0 {
		joined = append(joined, cur.String())
	}
	return joined
}

func firstTestableConfig(text string) string {
	for _, cfg := range joinConfigLines(text) {
		if strings.HasPrefix(cfg, "vless://") ||
			strings.HasPrefix(cfg, "trojan://") ||
			strings.HasPrefix(cfg, "vmess://") ||
			strings.HasPrefix(cfg, "ss://") {
			return cfg
		}
	}
	return ""
}
func extractSNI(cfg string) string {
	cfg = firstTestableConfig(cfg)
	if cfg == "" {
		return ""
	}
	var body string
	switch {
	case strings.HasPrefix(cfg, "vless://"):
		body = cfg[len("vless://"):]
	case strings.HasPrefix(cfg, "trojan://"):
		body = cfg[len("trojan://"):]
	default:
		return ""
	}
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	qi := strings.Index(body, "?")
	if qi < 0 {
		return ""
	}
	params := parseQueryParams(body[qi+1:])
	for _, k := range []string{"sni", "peer", "host"} {
		if v := params[k]; v != "" {
			return v
		}
	}
	return ""
}

func applyCustomDomain(cfg, customDomain string) string {
	if customDomain == "" {
		return cfg
	}
	return workersDevRegex.ReplaceAllString(cfg, customDomain)
}

func combineConfigs(configsText string, results []QualityResult, customDomain string, onlyProto string) []CombinedConfig {
	configsText = strings.TrimSpace(configsText)
	if configsText == "" {
		return nil
	}
	joined := joinConfigLines(configsText)
	parsed := make([]ParsedConfig, 0)
	for _, line := range joined {
		if strings.HasPrefix(line, "#") {
			continue
		}
		p, err := parseConfig(line)
		if err != nil {
			continue
		}
		parsed = append(parsed, p)
	}
	if len(parsed) == 0 {
		return nil
	}
	combined := make([]CombinedConfig, 0, len(parsed)*len(results))
	for i, p := range parsed {
		if onlyProto != "" && p.Proto != onlyProto {
			continue
		}
		for _, r := range results {
			newCfg, err := replaceConfig(p.Raw, r.IP)
			if err != nil {
				continue
			}
			newCfg = applyCustomDomain(newCfg, customDomain)
			combined = append(combined, CombinedConfig{
				IP: r.IP, Port: r.Port,
				Latency: r.LatencyAvg, Score: r.Score,
				PacketLoss: r.PacketLoss, Jitter: r.Jitter,
				XraySuccess: r.XraySuccess,
				Proto:       p.Proto, Config: newCfg, SourceIdx: i,
			})
		}
	}
	sort.Slice(combined, func(i, j int) bool { return combined[i].Score > combined[j].Score })
	return combined
}

// ==================== SCAN ====================
type ScanOptions struct {
	Workers        int
	Timeout        time.Duration
	MaxLatency     float64
	ConfigURI      string
	Ports          []int
	TestHost       string
	SmartFragment  bool
	CustomDomain   string
	UseXray        bool
	UseECH         bool
	ECHConfig      string
	UseIPv6        bool
	TopXray        int
	DoThroughput   bool
	UseHistory     bool
	HistoryAllowed bool
}

func scan(candidates []string, opts ScanOptions) []QualityResult {
	startTime := time.Now()

	// SNI resolution — اولویت به SNI کانفیگ
	testSNI := opts.TestHost
	if testSNI == "" {
		testSNI = extractSNI(opts.ConfigURI)
	}
	if testSNI == "" {
		testSNI = TestHost
	}
	if opts.CustomDomain != "" {
		testSNI = opts.CustomDomain
	}

	// History: IPهای موفق قبلی اول تست می‌شن
	if opts.UseHistory {
		historyMutex.Lock()
		known := make(map[string]bool)
		for k, e := range historyData {
			if e.Hits > 0 && time.Since(mustParseTime(e.LastTested)) < 24*time.Hour {
				if i := strings.LastIndex(k, ":"); i > 0 {
					known[k[:i]] = true
				}
			}
		}
		historyMutex.Unlock()
		if len(known) > 0 {
			prioritized := make([]string, 0, len(candidates))
			rest := make([]string, 0, len(candidates))
			for _, ip := range candidates {
				if known[ip] {
					prioritized = append(prioritized, ip)
				} else {
					rest = append(rest, ip)
				}
			}
			candidates = append(prioritized, rest...)
		}
	}

	// Phase 1
	setProgress(Progress{Phase: 1, PhaseName: "تست سریع TLS", Total: len(candidates), Message: "در حال تست TLS..."})

	type fastRes struct {
		ip   string
		port int
		lat  float64
	}
	jobs := make(chan string, opts.Workers)
	results := make(chan fastRes, 500)
	var wg sync.WaitGroup
	var processed int64

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]fastRes, 0, 16)
			for ip := range jobs {
				if isCancelled() {
					return
				}
				port, lat, ok := fastTestAllPorts(ip, opts.Ports, opts.Timeout, testSNI)
				atomic.AddInt64(&processed, 1)
				if ok && lat <= opts.MaxLatency {
					local = append(local, fastRes{ip, port, lat})
					if len(local) >= 16 {
						for _, r := range local {
							results <- r
						}
						local = local[:0]
					}
				}
			}
			for _, r := range local {
				results <- r
			}
		}()
	}

	go func() {
		for _, ip := range candidates {
			if isCancelled() {
				break
			}
			jobs <- ip
		}
		close(jobs)
	}()

	// progress updater
	go func() {
		for {
			if isCancelled() {
				return
			}
			done := int(atomic.LoadInt64(&processed))
			if done >= len(candidates) {
				return
			}
			updateProgress(func(p *Progress) {
				p.Done = done
				p.Elapsed = time.Since(startTime).Seconds()
			})
			time.Sleep(200 * time.Millisecond)
		}
	}()

	go func() { wg.Wait(); close(results) }()

	fastList := make([]fastRes, 0, 256)
	for r := range results {
		fastList = append(fastList, r)
	}

	sort.Slice(fastList, func(i, j int) bool { return fastList[i].lat < fastList[j].lat })
	if len(fastList) > MaxFastResults {
		fastList = fastList[:MaxFastResults]
	}
	if len(fastList) == 0 {
		return []QualityResult{}
	}

	// Phase 2
	setProgress(Progress{Phase: 2, PhaseName: "سنجش کیفیت", Total: len(fastList), Message: "در حال سنجش کیفیت..."})

	qw := qualityWorkers
	if qw > len(fastList) {
		qw = len(fastList)
	}
	qjobs := make(chan fastRes, qw)
	qresults := make(chan QualityResult, len(fastList))
	var qwg sync.WaitGroup
	var qprocessed int64

	for i := 0; i < qw; i++ {
		qwg.Add(1)
		go func() {
			defer qwg.Done()
			for r := range qjobs {
				if isCancelled() {
					return
				}
				qr := measureQuality(r.ip, r.port, opts.Timeout, 10, testSNI)
				atomic.AddInt64(&qprocessed, 1)
				qresults <- qr
			}
		}()
	}

	// Phase 2 progress updater — mirrors qprocessed into the UI.
	go func() {
		for {
			if isCancelled() {
				return
			}
			done := int(atomic.LoadInt64(&qprocessed))
			if done >= len(fastList) {
				return
			}
			updateProgress(func(p *Progress) {
				p.Done = done
				p.Elapsed = time.Since(startTime).Seconds()
			})
			time.Sleep(200 * time.Millisecond)
		}
	}()

	go func() {
		for _, r := range fastList {
			if isCancelled() {
				break
			}
			qjobs <- r
		}
		close(qjobs)
	}()
	go func() { qwg.Wait(); close(qresults) }()

	final := make([]QualityResult, 0, len(fastList))
	for r := range qresults {
		if r.PacketLoss >= 50 || r.LatencyAvg >= 9999 || r.Jitter >= 500 {
			continue
		}
		// NOTE: fingerprint detection was intentionally removed from this
		// serial loop. The Fingerprint field is not consumed downstream,
		// and running up to 3 extra TLS handshakes per IP in the main
		// goroutine dominated phase-2 wall time.
		r.Score = calculateScore(r)
		final = append(final, r)
	}
	sort.Slice(final, func(i, j int) bool { return final[i].Score > final[j].Score })

	// Phase 3 - Xray (only if enabled)
	firstTestable := firstTestableConfig(opts.ConfigURI)
	if opts.UseXray && firstTestable != "" && findXrayBinary() != "" {
		topN := opts.TopXray
		if topN <= 0 {
			topN = DefaultTop
		}
		if topN > len(final) {
			topN = len(final)
		}

		setProgress(Progress{Phase: 3, PhaseName: "اعتبارسنجی Xray", Total: topN, Message: "در حال تست Xray..."})

		sem := make(chan struct{}, 10)
		var xwg sync.WaitGroup
		var xdone int64
		for i := 0; i < topN; i++ {
			xwg.Add(1)
			sem <- struct{}{}
			go func(idx int) {
				defer xwg.Done()
				defer func() { <-sem }()
				defer func() {
					atomic.AddInt64(&xdone, 1)
					updateProgress(func(p *Progress) {
						p.Done = int(atomic.LoadInt64(&xdone))
						p.Elapsed = time.Since(startTime).Seconds()
					})
				}()
				if isCancelled() {
					return
				}
				tunnelPort := SocksPort + idx
				lat := testWithXray(firstTestable, final[idx].IP, final[idx].Port,
					tunnelPort, 8*time.Second, opts.SmartFragment, "", opts.ECHConfig)
				if lat != nil {
					final[idx].TunnelLatency = lat
					success := true
					final[idx].XraySuccess = &success
					// Throughput test for verified IPs
					if opts.DoThroughput {
						mbps := measureThroughput(final[idx].IP, final[idx].Port, testSNI, 5*time.Second)
						final[idx].SpeedMbps = mbps
					}
					final[idx].Score = calculateScore(final[idx])
					updateHistory(final[idx].IP, final[idx].Port, true, final[idx].LatencyAvg)
				} else {
					failure := false
					final[idx].XraySuccess = &failure
					updateHistory(final[idx].IP, final[idx].Port, false, 0)
				}
			}(i)
		}
		xwg.Wait()
		sort.Slice(final, func(i, j int) bool { return final[i].Score > final[j].Score })
	} else if opts.DoThroughput {
		// throughput on top 10 even without Xray
		topN := 10
		if topN > len(final) {
			topN = len(final)
		}
		for i := 0; i < topN; i++ {
			mbps := measureThroughput(final[i].IP, final[i].Port, testSNI, 5*time.Second)
			final[i].SpeedMbps = mbps
			final[i].Score = calculateScore(final[i])
		}
		sort.Slice(final, func(i, j int) bool { return final[i].Score > final[j].Score })
	}

	if opts.HistoryAllowed {
		saveHistory()
	}
	return final
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ==================== HTTP ====================
type ScanRequest struct {
	Samples        int     `json:"samples"`
	Workers        int     `json:"workers"`
	Timeout        float64 `json:"timeout"`
	MaxLatency     float64 `json:"max_latency"`
	TestHost       string  `json:"test_host"`
	Config         string  `json:"config"`
	Ports          []int   `json:"ports"`
	OnlyXray       bool    `json:"only_xray"`
	SmartFragment  bool    `json:"smart_fragment"`
	CustomDomain   string  `json:"custom_domain"`
	UseXray        bool    `json:"use_xray"`
	UseECH         bool    `json:"use_ech"`
	ECHConfig      string  `json:"ech_config"`
	UseIPv6        bool    `json:"use_ipv6"`
	TopXray        int     `json:"top_xray"`
	DoThroughput   bool    `json:"do_throughput"`
	UseHistory     bool    `json:"use_history"`
	HistoryAllowed bool    `json:"history_allowed"`
}

type ScanResponse struct {
	TotalTested   int              `json:"total_tested"`
	TotalAlive    int              `json:"total_alive"`
	ElapsedSec    float64          `json:"elapsed_sec"`
	RangesCount   int              `json:"ranges_count"`
	Results       []QualityResult  `json:"results"`
	Combined      []CombinedConfig `json:"combined"`
	CombinedCount int              `json:"combined_count"`
	XrayFiltered  bool             `json:"xray_filtered"`
	XrayPassed    int              `json:"xray_passed"`
	OnlyXray      bool             `json:"only_xray"`
	Error         string           `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, ScanResponse{Error: "method not allowed"})
		return
	}
	var req ScanRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ScanResponse{Error: err.Error()})
		return
	}

	if !scanInProgress.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusConflict, ScanResponse{Error: "a scan is already in progress"})
		return
	}
	defer scanInProgress.Store(false)

	if req.Samples <= 0 {
		req.Samples = DefaultSamples
	}
	if req.Samples > 500 {
		req.Samples = 500
	}
	if req.Workers <= 0 {
		req.Workers = defaultWorkers
	}
	if req.Workers > 2000 {
		req.Workers = 2000
	}
	if req.Timeout <= 0 {
		req.Timeout = 2
	}
	if req.Timeout > 30 {
		req.Timeout = 30
	}
	if req.MaxLatency <= 0 {
		req.MaxLatency = DefaultMaxLat
	}
	if req.MaxLatency > 5000 {
		req.MaxLatency = 5000
	}
	if len(req.Ports) == 0 {
		req.Ports = defaultPorts
	}

	invalidateRanges()
	ranges := fetchRanges(req.UseIPv6)
	candidates := make([]string, 0, len(ranges)*req.Samples)
	seen := make(map[string]struct{})
	for _, cidr := range ranges {
		for _, ip := range sampleRange(cidr, req.Samples) {
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				candidates = append(candidates, ip)
				if len(candidates) >= MaxCandidates {
					break
				}
			}
		}
		if len(candidates) >= MaxCandidates {
			break
		}
	}
	if len(candidates) == 0 {
		writeJSON(w, http.StatusOK, ScanResponse{Error: "no candidates"})
		return
	}

	// Setup cancel channel
	cancelCh := make(chan struct{})
	cancelMutex.Lock()
	scanCancel.Store(cancelCh)
	cancelClosed = false
	cancelMutex.Unlock()
	clearTLSCache()
	refreshXrayPath()
	setProgress(Progress{Phase: 1, PhaseName: "شروع", Total: len(candidates), Message: "شروع اسکن..."})

	t0 := time.Now()
	timeout := time.Duration(req.Timeout * float64(time.Second))
	echConfig := ""
	if req.UseECH {
		echConfig = req.ECHConfig
	}
	results := scan(candidates, ScanOptions{
		Workers:        req.Workers,
		Timeout:        timeout,
		MaxLatency:     req.MaxLatency,
		ConfigURI:      req.Config,
		Ports:          req.Ports,
		TestHost:       req.TestHost,
		SmartFragment:  req.SmartFragment,
		CustomDomain:   req.CustomDomain,
		UseXray:        req.UseXray,
		UseECH:         req.UseECH,
		ECHConfig:      echConfig,
		UseIPv6:        req.UseIPv6,
		TopXray:        req.TopXray,
		DoThroughput:   req.DoThroughput,
		UseHistory:     req.UseHistory,
		HistoryAllowed: req.HistoryAllowed,
	})
	elapsed := time.Since(t0).Seconds()

	// Drop IPs that did not survive the quality phase
	// (100% loss, unreachable, or timed out).
	clean := results[:0]
	for _, r := range results {
		if r.PacketLoss < 50 && r.LatencyAvg < 9999 {
			clean = append(clean, r)
		}
	}
	results = clean
	if len(results) > DefaultTop {
		results = results[:DefaultTop]
	}

	for i := range results {
		results[i].LatencyAvg = roundTo(results[i].LatencyAvg, 1)
		results[i].Jitter = roundTo(results[i].Jitter, 1)
		results[i].PacketLoss = roundTo(results[i].PacketLoss, 1)
		results[i].Score = roundTo(results[i].Score, 2)
		results[i].SpeedMbps = roundTo(results[i].SpeedMbps, 2)
		if results[i].TunnelLatency != nil {
			v := roundTo(*results[i].TunnelLatency, 1)
			results[i].TunnelLatency = &v
		}
	}

	alive := len(results)

	var combineInput []QualityResult
	xrayFiltered := false
	xrayPassed := 0
	firstTestable := firstTestableConfig(req.Config)
	testedProto := ""
	if firstTestable != "" {
		if i := strings.Index(firstTestable, "://"); i > 0 {
			testedProto = firstTestable[:i]
		}
	}
	if req.UseXray && firstTestable != "" && findXrayBinary() != "" {
		xrayFiltered = true
		filtered := make([]QualityResult, 0)
		for _, r := range results {
			if r.XraySuccess != nil && *r.XraySuccess {
				filtered = append(filtered, r)
			}
		}
		xrayPassed = len(filtered)
		// IMPORTANT: Always include ALL results in combined, regardless of
		// the OnlyXray flag. The Advanced toggle `only_xray` only affects
		// the "Top IPs" table on the server side. Combined configs must
		// contain everything so the client-side filter can toggle freely.
		combineInput = results
	} else {
		combineInput = results
		testedProto = ""
	}
	combined := combineConfigs(req.Config, combineInput, req.CustomDomain, testedProto)

	writeJSON(w, http.StatusOK, ScanResponse{
		TotalTested: len(candidates), TotalAlive: alive,
		ElapsedSec: roundTo(elapsed, 2), RangesCount: len(ranges),
		Results: results, Combined: combined, CombinedCount: len(combined),
		XrayFiltered: xrayFiltered, XrayPassed: xrayPassed, OnlyXray: req.OnlyXray,
	})
}

func progressHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, getProgress())
}

var cancelMutex sync.Mutex
var cancelClosed bool
var scanInProgress atomic.Bool

func cancelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	cancelMutex.Lock()
	if !cancelClosed {
		v := scanCancel.Load()
		if v != nil {
			if ch, ok := v.(chan struct{}); ok && ch != nil {
				select {
				case <-ch:
				default:
					close(ch)
				}
				cancelClosed = true
			}
		}
	}
	cancelMutex.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func clearHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "DELETE or POST required", http.StatusMethodNotAllowed)
		return
	}
	historyMutex.Lock()
	historyData = map[string]HistoryEntry{}
	historyMutex.Unlock()
	if err := os.Remove(HistoryFile); err != nil && !os.IsNotExist(err) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Format  string           `json:"format"`
		Configs []CombinedConfig `json:"configs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	switch req.Format {
	case "clash":
		var sb strings.Builder
		sb.WriteString("proxies:\n")
		for i, c := range req.Configs {
			sb.WriteString(fmt.Sprintf("  - name: \"clean-%d\"\n", i+1))
			sb.WriteString(fmt.Sprintf("    type: vless\n"))
			sb.WriteString(fmt.Sprintf("    server: %s\n", c.IP))
			sb.WriteString(fmt.Sprintf("    port: %d\n", 443))
			sb.WriteString("    udp: true\n")
			sb.WriteString("    tls: true\n")
		}
		writeJSON(w, http.StatusOK, map[string]string{"content": sb.String(), "format": "clash"})
	case "singbox":
		out := map[string]interface{}{"outbounds": req.Configs}
		writeJSON(w, http.StatusOK, out)
	default:
		writeJSON(w, http.StatusOK, map[string]interface{}{"configs": req.Configs})
	}
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/index.html":
		w.Header().Set("X-CleanIP-Finder", "1")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(embeddedIndexHTML)
	case "/style.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(embeddedStyleCSS)
	default:
		http.NotFound(w, r)
	}
}

// ==================== MAIN ====================
func isOurServerRunning(port int) bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 100)
	return resp.Header.Get("X-CleanIP-Finder") == "1"
}

func findFreePort(start int) int {
	for p := start; p < start+100; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln.Close()
			return p
		}
	}
	return start
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func showAlert(msg string) {
	if runtime.GOOS != "windows" {
		return
	}
	safe := strings.ReplaceAll(msg, "'", "\\'")
	safe = strings.ReplaceAll(safe, "\r", "")
	safe = strings.ReplaceAll(safe, "\n", "\\n")
	script := fmt.Sprintf(`javascript:alert('%s');close();`, safe)
	_ = exec.Command("mshta", script).Start()
}

var shutdownRequested = make(chan struct{}, 1)

func shutdownHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"shutting_down"}`))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		select {
		case shutdownRequested <- struct{}{}:
		default:
		}
	}()
}

func main() {
	exePath, err := os.Executable()
	if err == nil {
		_ = os.Chdir(filepath.Dir(exePath))
	}
	log.SetOutput(io.Discard)
	loadHistory()

	if isOurServerRunning(APIPort) {
		openBrowser(fmt.Sprintf("http://localhost:%d", APIPort))
		return
	}

	port := findFreePort(APIPort)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := fmt.Sprintf("http://localhost:%d", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/", staticHandler)
	mux.HandleFunc("/api/scan", scanHandler)
	mux.HandleFunc("/api/progress", progressHandler)
	mux.HandleFunc("/api/cancel", cancelHandler)
	mux.HandleFunc("/api/history", clearHistoryHandler)
	mux.HandleFunc("/api/export", exportHandler)
	mux.HandleFunc("/api/shutdown", shutdownHandler)
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CleanIP-Finder", "1")
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr: addr, Handler: mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		showAlert(fmt.Sprintf("خطا: %v", err))
		return
	}

	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	go func() { time.Sleep(700 * time.Millisecond); openBrowser(url) }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-shutdownRequested:
	case <-sigCh:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
