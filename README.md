# ip-investigator

A CLI tool that queries 9 threat-intel APIs concurrently and renders a colored terminal report with a Gemini AI summary.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)

## Features

- Concurrent lookups across 9 sources — results in seconds
- Colored terminal output with status indicators
- AI summary powered by Gemini

## Sources

| Tool | Type |
|---|---|
| IPInfo | Geolocation, ASN, ISP |
| Reverse DNS | PTR record |
| WHOIS | Netblock, org, abuse contact |
| VirusTotal | Malware detections |
| Google Threat Intelligence | Verdict & severity |
| AbuseIPDB | Abuse score & reports |
| GreyNoise | Background noise classification |
| AlienVault OTX | Threat pulses |
| Shodan | Open ports & last scan |

## Requirements

- Go 1.21+
- API keys for the services you want to use

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/aivxx02/ip-investigator.git
cd ip-investigator
```

**2. Create a `.env` file** next to the binary:
```env
IPINFO_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
GOOGLE_TI_KEY=your_key_here
ABUSEIPDB_KEY=your_key_here
GREYNOISE_KEY=your_key_here
OTX_KEY=your_key_here
SHODAN_KEY=your_key_here
GEMINI_KEY=your_key_here
```

All keys are optional — enrichers with missing keys will show as errors in the report.

**3. Build**
```bash
go build -o ip-investigator.exe .   # Windows
go build -o ip-investigator .       # Linux/macOS
```

**4. Run**
```bash
./ip-investigator.exe <ip>
./ip-investigator.exe 1.1.1.1
```

## API Keys

| Service | Free Tier | Link |
|---|---|---|
| IPInfo | 50k req/month | https://ipinfo.io |
| VirusTotal | 500 req/day | https://virustotal.com |
| Google TI | Limited free | https://cloud.google.com/threat-intelligence |
| AbuseIPDB | 1k req/day | https://abuseipdb.com |
| GreyNoise | Community free | https://greynoise.io |
| AlienVault OTX | Free | https://otx.alienvault.com |
| Shodan | Free (limited) | https://shodan.io |
| Gemini | Free tier | https://aistudio.google.com |

## Status Legend

| Icon | Meaning |
|---|---|
| ✅ | Data retrieved successfully |
| ⚠️ | Partial data (API rate limit) |
| ❌ | No data found |
| 🚫 | API error / unreachable |
