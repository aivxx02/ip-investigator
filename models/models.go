package models

import (
	"strings"
	"time"
)

// Status represents the outcome of an enricher call.
type Status int

const (
	StatusOK      Status = iota // ✅ data retrieved
	StatusPartial               // ⚠️ partial data (API limit)
	StatusNoData                // ❌ no results found
	StatusError                 // 🚫 API error / timeout
)

func (s Status) Icon() string {
	switch s {
	case StatusOK:
		return "✅"
	case StatusPartial:
		return "⚠️"
	case StatusNoData:
		return "❌"
	case StatusError:
		return "🚫"
	default:
		return "?"
	}
}

// EnrichResult is the generic wrapper returned by every enricher.
type EnrichResult struct {
	Tool    string
	Status  Status
	Note    string        // shown in status table when non-empty
	Data    any           // cast to tool-specific struct in report renderer
	Index   int           // position in the original enricher slice
	Elapsed time.Duration // time taken by this enricher
}

// --- Tool-specific result structs ---

type GeoResult struct {
	Country string
	City    string
	ISP     string
	ASN     string
	OrgType string // e.g. "Hosting / Datacenter"
}

type ReverseDNSResult struct {
	PTR string
}

type WHOISResult struct {
	Netblock   string
	Org        string
	AbuseEmail string
	Registered string
}

type VirusTotalResult struct {
	Detections int
	Total      int
	Categories []string
	PassiveDNS int
	LastSeen   string
}

type GoogleTIResult struct {
	Verdict   string // "malicious", "suspicious", "harmless", "undetected"
	Actor     string
	Campaigns int
}

type AbuseIPDBResult struct {
	Score      int
	Reports    int
	LastReport string
	Categories []string
}

type GreyNoiseResult struct {
	Classification string // "malicious", "benign", "unknown"
	LastSeen       string
	Tags           []string
}

type OTXResult struct {
	Pulses   int
	Malware  []string
	LastSeen string
}

type ShodanResult struct {
	Ports    []int
	Banners  []string
	CVEs     []string
	LastScan string
}

// ParseOrg splits "AS13335 Cloudflare, Inc." into ("AS13335", "Cloudflare, Inc.").
func ParseOrg(org string) (asn, isp string) {
	parts := strings.SplitN(org, " ", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return org, org
}
