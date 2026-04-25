# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build ./...
go build -o ip-investigator.exe .   # named binary (Windows)

# Run
./ip-investigator.exe <ip>
./ip-investigator.exe 8.8.8.8

# Test all packages
go test ./...

# Test a single package
go test ./enrichers/...
go test ./models/...
go test ./config/...
go test ./summary/...
go test ./report/...

# Test a single test function
go test ./enrichers/ -run TestIPInfo_Success -v

# Tidy modules
go mod tidy
```

## Architecture

The tool queries 9 threat-intel APIs concurrently, renders a live per-tool progress ticker, then shows a colored terminal report with an optional OpenRouter AI summary.

**Data flow:**
```
main.go → config.Load() → enrichers.RunAllLive() → progress.Tracker → summary.OpenRouter.Summarize() → report.Render()
```

**Package responsibilities:**

- `models/` — shared result types only. All tool-specific result structs (`GeoResult`, `VirusTotalResult`, etc.), the `Status` enum (OK/Partial/NoData/Error), and `EnrichResult` wrapper live here. `EnrichResult` carries `Index int` (position in enricher slice) and `Elapsed time.Duration` (set by `RunAllLive`). No logic beyond `Status.Icon()` and `ParseOrg()`.

- `config/` — loads API keys from `.env` beside the binary via `godotenv`. `Load()` uses `os.Executable()` to find the binary directory. `LoadFrom(path)` is the testable variant used in tests.

- `enrichers/` — one file per API source. All implement `Enricher` interface (`Name() string`, `Enrich(ctx, ip) EnrichResult`). Two runners in `enricher.go`: `RunAll()` returns results in original order (used by tests); `RunAllLive()` streams results to a channel as each enricher finishes (sets `Index` and `Elapsed` on each result, closes channel when done — used by `main.go`). HTTP-based enrichers have unexported `baseURL` and `timeout` fields for test injection (use `httptest.NewServer` — no real HTTP calls in tests).

- `summary/` — calls OpenRouter REST API (`openrouter.ai/api/v1/chat/completions`, no SDK). Builds a structured prompt that includes each enricher's status icon so the AI can acknowledge data gaps in its assessment. Model defaults to `google/gemma-2-9b-it:free`; override with `OPENROUTER_MODEL`.

- `progress/` — live per-tool progress display using raw ANSI escape codes (no extra deps). `Tracker` methods: `Start(ip, names)`, `Complete(idx, status, elapsed, note)`, `StartAI()`, `DoneAI(elapsed)`, `Clear()`. `Clear()` is idempotent (safe to call multiple times or before `Start()`). Spinner goroutine runs at 80 ms tick; stopped via `stop` channel with `sync.Once`.

- `report/` — renders colored terminal output using `fatih/color`. Every section renders even if empty/errored — nothing is silently skipped.

## Enricher Pattern

API-keyed enrichers (IPInfo, VirusTotal, GoogleTI, AbuseIPDB, GreyNoise, OTX, Shodan):
```go
type ToolName struct {
    Key     string        // API key (empty = return StatusError immediately)
    baseURL string        // default: production URL; override in tests
    timeout time.Duration // default: 10s; override in tests
}
```

Keyless enrichers use injectable function fields instead:
- `ReverseDNS{lookup func(ctx, addr) ([]string, error)}` — wraps `net.DefaultResolver.LookupAddr`
- `WHOIS{query func(host) (string, error)}` — wraps `gowhois.Whois`

Status codes returned:
- `StatusOK` — data retrieved
- `StatusPartial` — HTTP 429 rate limit hit
- `StatusNoData` — HTTP 404 or empty result
- `StatusError` — no key, request failed, parse error, timeout

## API Keys

Create `.env` in the same directory as the binary. Keys read from environment variables (`VIRUSTOTAL_KEY`, `GOOGLE_TI_KEY`, `ABUSEIPDB_KEY`, `GREYNOISE_KEY`, `OTX_KEY`, `SHODAN_KEY`, `IPINFO_KEY`, `OPENROUTER_KEY`, `OPENROUTER_MODEL`). Environment variables already set take precedence over `.env`.

## Repository

GitHub: https://github.com/aivxx02/ip-investigator.git

`.gitignore` excludes `.env` and `*.exe` — never commit API keys.

```bash
# Git
git add .
git commit -m "message"
git push
```

## IDE Diagnostics

The IDE (VS Code / LSP) frequently shows stale "undefined" errors in `_test.go` files when the implementation file is created in the same session. These are false positives — `go test ./...` is the authoritative check.