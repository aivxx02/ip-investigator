package report

import (
	"bytes"
	"strings"
	"testing"

	"ip-investigator/models"
)

func TestRender_ContainsAllSections(t *testing.T) {
	results := []models.EnrichResult{
		{Tool: "ipinfo.io", Status: models.StatusOK, Data: models.GeoResult{Country: "DE", City: "Frankfurt", ASN: "AS23764", ISP: "Frantech Solutions"}},
		{Tool: "Reverse DNS", Status: models.StatusOK, Data: models.ReverseDNSResult{PTR: "tor-exit.example.com"}},
		{Tool: "WHOIS", Status: models.StatusOK, Data: models.WHOISResult{Netblock: "185.220.100.0/22", Org: "Frantech Solutions", AbuseEmail: "abuse@frantech.ca"}},
		{Tool: "VirusTotal", Status: models.StatusOK, Data: models.VirusTotalResult{Detections: 12, Total: 94, Categories: []string{"malware", "C2"}}},
		{Tool: "Google TI", Status: models.StatusNoData},
		{Tool: "AbuseIPDB", Status: models.StatusPartial, Note: "daily limit reached"},
		{Tool: "GreyNoise", Status: models.StatusError, Note: "timeout"},
		{Tool: "AlienVault OTX", Status: models.StatusNoData},
		{Tool: "Shodan", Status: models.StatusOK, Data: models.ShodanResult{Ports: []int{22, 443}, CVEs: []string{"CVE-2023-38408"}}},
	}

	var buf bytes.Buffer
	Render(&buf, "185.220.101.45", results, "Risk Level: CRITICAL\nRecommended Action: Block immediately")

	output := buf.String()
	for _, want := range []string{
		"185.220.101.45",
		"GEOLOCATION",
		"Frankfurt",
		"VIRUSTOTAL",
		"12/94",
		"STATUS",
		"CRITICAL",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestRender_AllSectionsPresent(t *testing.T) {
	// Every tool section must appear even when status is NoData or Error
	results := []models.EnrichResult{
		{Tool: "ipinfo.io", Status: models.StatusNoData},
		{Tool: "Reverse DNS", Status: models.StatusError, Note: "timeout"},
		{Tool: "WHOIS", Status: models.StatusNoData},
		{Tool: "VirusTotal", Status: models.StatusError, Note: "no key"},
		{Tool: "Google TI", Status: models.StatusNoData},
		{Tool: "AbuseIPDB", Status: models.StatusNoData},
		{Tool: "GreyNoise", Status: models.StatusNoData},
		{Tool: "AlienVault OTX", Status: models.StatusNoData},
		{Tool: "Shodan", Status: models.StatusNoData},
	}

	var buf bytes.Buffer
	Render(&buf, "1.2.3.4", results, "")

	output := buf.String()
	for _, tool := range []string{"IPINFO", "REVERSE DNS", "WHOIS", "VIRUSTOTAL", "GOOGLE TI", "ABUSEIPDB", "GREYNOISE", "ALIENVAULT OTX", "SHODAN"} {
		if !strings.Contains(output, tool) {
			t.Errorf("section missing for tool %q", tool)
		}
	}
}
