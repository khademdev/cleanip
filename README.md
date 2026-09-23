# CleanIP

Smart multi-stage Cloudflare clean-IP finder.

## Features

- Parallel TLS testing with up to 2000 workers
- Real Xray tunnel validation (VLESS / VMess / Trojan / Shadowsocks)
- Quality scoring: latency, jitter, packet loss, download speed
- Smart Fragment for Iranian DPI bypass
- ECH (Encrypted Client Hello) support
- IPv4 + IPv6 dual-stack
- Bilingual UI (Persian / English)
- Opt-in history file (privacy-first)
- Zero external dependencies (Go stdlib only)
- No console window on Windows

## Download

Get the latest binary from the Releases page.

## Quick start

1. Run `cleanip.exe`
2. Browser opens automatically at http://localhost:8080
3. Paste your V2Ray config (optional)
4. Pick a preset and click Start Scan

## Privacy

- No telemetry
- All traffic on 127.0.0.1
- History is opt-in

## Build from source

```bash
git clone https://github.com/khademdev/cleanip.git
cd cleanip
make build
```

## License

MIT - Copyright (c) 2025 Meysam Khademshams
