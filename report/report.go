package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"

	"ip-investigator/models"
)

// Render writes the full colored terminal report to w.
// color output is forced to w so tests can capture it via bytes.Buffer.
func Render(w io.Writer, ip string, results []models.EnrichResult, aiSummary string) {
	color.Output = w
	color.NoColor = false

	printBox(w, ip)
	for _, r := range results {
		printSection(w, r)
	}
	printStatusTable(w, results)
	printAISummary(w, aiSummary)
}

func printBox(w io.Writer, ip string) {
	fmt.Fprintln(w, "╔══════════════════════════════════════════╗")
	color.New(color.FgWhite, color.Bold).Fprintf(w, "║        IP INVESTIGATION REPORT           ║\n")
	fmt.Fprintf(w, "║        Target: %-27s║\n", ip)
	fmt.Fprintf(w, "║        Time  : %-27s║\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintln(w, "╚══════════════════════════════════════════╝")
	fmt.Fprintln(w)
}

func printSection(w io.Writer, r models.EnrichResult) {
	color.New(color.FgCyan, color.Bold).Fprintf(w, "[%s]\n", strings.ToUpper(sectionTitle(r.Tool)))

	switch r.Status {
	case models.StatusNoData:
		color.New(color.FgHiBlack).Fprintf(w, "  ❌  No data found\n")
	case models.StatusError:
		color.New(color.FgRed, color.Bold).Fprintf(w, "  🚫  %s\n", r.Note)
	case models.StatusPartial:
		color.New(color.FgYellow).Fprintf(w, "  ⚠️   Partial data: %s\n", r.Note)
		printData(w, r)
	case models.StatusOK:
		printData(w, r)
	}
	fmt.Fprintln(w)
}

func printData(w io.Writer, r models.EnrichResult) {
	if r.Data == nil {
		return
	}
	switch d := r.Data.(type) {
	case models.GeoResult:
		field(w, "Country", d.Country)
		field(w, "City", d.City)
		field(w, "ISP", d.ISP)
		field(w, "ASN", d.ASN)
	case models.ReverseDNSResult:
		field(w, "PTR Record", d.PTR)
	case models.WHOISResult:
		field(w, "Netblock", d.Netblock)
		field(w, "Org", d.Org)
		field(w, "Abuse Email", d.AbuseEmail)
		field(w, "Registered", d.Registered)
	case models.VirusTotalResult:
		val := fmt.Sprintf("%d/%d engines flagged", d.Detections, d.Total)
		if d.Detections > 0 {
			color.New(color.FgRed, color.Bold).Fprintf(w, "  %-16s: %s\n", "Detections", val)
		} else {
			color.New(color.FgGreen).Fprintf(w, "  %-16s: %s\n", "Detections", val)
		}
		field(w, "Categories", strings.Join(d.Categories, ", "))
	case models.GoogleTIResult:
		verdictColor(w, d.Verdict)
		field(w, "Actor", d.Actor)
		if d.Campaigns > 0 {
			field(w, "Campaigns", fmt.Sprintf("%d active campaigns linked", d.Campaigns))
		}
	case models.AbuseIPDBResult:
		scoreField(w, d.Score)
		field(w, "Reports", fmt.Sprintf("%d reports", d.Reports))
		field(w, "Last Report", d.LastReport)
	case models.GreyNoiseResult:
		classField(w, d.Classification)
		field(w, "Last Seen", d.LastSeen)
	case models.OTXResult:
		field(w, "Pulses", fmt.Sprintf("%d threat campaigns matched", d.Pulses))
		field(w, "Last Seen", d.LastSeen)
	case models.ShodanResult:
		ports := make([]string, len(d.Ports))
		for i, p := range d.Ports {
			ports[i] = fmt.Sprintf("%d", p)
		}
		field(w, "Open Ports", strings.Join(ports, ", "))
		field(w, "Banners", strings.Join(d.Banners, ", "))
		if len(d.CVEs) > 0 {
			color.New(color.FgRed, color.Bold).Fprintf(w, "  %-16s: %s\n", "CVEs", strings.Join(d.CVEs, ", "))
		}
		field(w, "Last Scan", d.LastScan)
	}
}

func field(w io.Writer, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(w, "  %-16s: %s\n", label, value)
}

func verdictColor(w io.Writer, verdict string) {
	switch strings.ToLower(verdict) {
	case "malicious", "critical":
		color.New(color.FgRed, color.Bold).Fprintf(w, "  %-16s: %s\n", "Verdict", verdict)
	case "suspicious":
		color.New(color.FgYellow).Fprintf(w, "  %-16s: %s\n", "Verdict", verdict)
	default:
		color.New(color.FgGreen).Fprintf(w, "  %-16s: %s\n", "Verdict", verdict)
	}
}

func scoreField(w io.Writer, score int) {
	val := fmt.Sprintf("%d%%", score)
	switch {
	case score >= 75:
		color.New(color.FgRed, color.Bold).Fprintf(w, "  %-16s: %s\n", "Abuse Score", val)
	case score >= 25:
		color.New(color.FgYellow).Fprintf(w, "  %-16s: %s\n", "Abuse Score", val)
	default:
		color.New(color.FgGreen).Fprintf(w, "  %-16s: %s\n", "Abuse Score", val)
	}
}

func classField(w io.Writer, classification string) {
	switch strings.ToLower(classification) {
	case "malicious":
		color.New(color.FgRed, color.Bold).Fprintf(w, "  %-16s: Targeted attacker\n", "Status")
	case "benign":
		color.New(color.FgGreen).Fprintf(w, "  %-16s: Background noise (benign)\n", "Status")
	default:
		color.New(color.FgYellow).Fprintf(w, "  %-16s: %s\n", "Status", classification)
	}
}

func printStatusTable(w io.Writer, results []models.EnrichResult) {
	fmt.Fprintln(w, strings.Repeat("─", 45))
	color.New(color.FgWhite, color.Bold).Fprintln(w, "  STATUS LEGEND")
	fmt.Fprintln(w, "  ✅  Data retrieved successfully")
	fmt.Fprintln(w, "  ⚠️  Partial data (API limit reached)")
	fmt.Fprintln(w, "  ❌  No data found")
	fmt.Fprintln(w, "  🚫  API error / unreachable")
	fmt.Fprintln(w, strings.Repeat("─", 45))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-20s %-6s %s\n", "Tool", "Status", "Note")
	fmt.Fprintf(w, "  %-20s %-6s %s\n", strings.Repeat("─", 18), strings.Repeat("─", 6), strings.Repeat("─", 25))
	for _, r := range results {
		fmt.Fprintf(w, "  %-20s %s  %s\n", r.Tool, r.Status.Icon(), r.Note)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("─", 45))
}

func printAISummary(w io.Writer, summary string) {
	color.New(color.FgWhite, color.Bold).Fprintln(w, "  AI SUMMARY  (OpenRouter)")
	fmt.Fprintln(w, strings.Repeat("─", 45))
	if summary == "" {
		color.New(color.FgHiBlack).Fprintln(w, "  (no summary available)")
	} else {
		for _, line := range strings.Split(summary, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "Risk Level:") {
				if strings.Contains(trimmed, "CRITICAL") || strings.Contains(trimmed, "HIGH") {
					color.New(color.FgRed, color.Bold).Fprintf(w, "  %s\n", trimmed)
				} else {
					color.New(color.FgYellow).Fprintf(w, "  %s\n", trimmed)
				}
			} else {
				fmt.Fprintf(w, "  %s\n", line)
			}
		}
	}
	fmt.Fprintln(w, strings.Repeat("─", 45))
}

func sectionTitle(tool string) string {
	if tool == "ipinfo.io" {
		return "GEOLOCATION — ipinfo.io"
	}
	return tool
}
