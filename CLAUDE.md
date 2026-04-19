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

# Tidy modules (run after all packages are implemented)
go mod tidy
```

## Architecture

The tool queries 9 threat-intel APIs concurrently and renders a colored terminal report with a Gemini AI summary.

**Data flow:**
```
main.go → config.Load() → enrichers.RunAll() → summary.Gemini.Summarize() → report.Render()
```

**Package responsibilities:**

- `models/` — shared result types only. All tool-specific result structs (`GeoResult`, `VirusTotalResult`, etc.), the `Status` enum (OK/Partial/NoData/Error), and `EnrichResult` wrapper live here. No logic beyond `Status.Icon()` and `ParseOrg()`.

- `config/` — loads API keys from `.env` beside the binary via `godotenv`. `Load()` uses `os.Executable()` to find the binary directory. `LoadFrom(path)` is the testable variant used in tests.

- `enrichers/` — one file per API source. All implement `Enricher` interface (`Name() string`, `Enrich(ctx, ip) EnrichResult`). `RunAll()` in `enricher.go` fans them out into goroutines and collects results in original order using index-based writes to a pre-allocated slice. Each enricher struct has unexported `baseURL` and `timeout` fields for test injection (no real HTTP calls in tests — use `httptest.NewServer`).

- `summary/` — calls Gemini REST API directly (no SDK). Builds a structured prompt that includes each enricher's status icon so Gemini can acknowledge data gaps in its assessment.

- `report/` — renders colored terminal output using `fatih/color`. Every section renders even if empty/errored — nothing is silently skipped.

## Enricher Pattern

Every enricher follows the same structure:
```go
type ToolName struct {
    Key     string        // API key (empty = return StatusError immediately)
    baseURL string        // default: production URL; override in tests
    timeout time.Duration // default: 10s; override in tests
}
```

Status codes returned:
- `StatusOK` — data retrieved
- `StatusPartial` — HTTP 429 rate limit hit
- `StatusNoData` — HTTP 404 or empty result
- `StatusError` — no key, request failed, parse error, timeout

## API Keys

Copy `.env.example` → `.env` in the same directory as the binary. Keys read from environment variables (`VIRUSTOTAL_KEY`, `GOOGLE_TI_KEY`, `ABUSEIPDB_KEY`, `GREYNOISE_KEY`, `OTX_KEY`, `SHODAN_KEY`, `IPINFO_KEY`, `GEMINI_KEY`). Environment variables already set take precedence over `.env`.

## IDE Diagnostics

The IDE (VS Code / LSP) frequently shows stale "undefined" errors in `_test.go` files when the implementation file is created in the same session. These are false positives — `go test ./...` is the authoritative check.
