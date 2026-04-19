package enrichers

import (
	"context"
	"strings"

	gowhois "github.com/likexian/whois"

	"ip-investigator/models"
)

type WHOIS struct {
	query func(host string) (string, error)
}

func (e *WHOIS) Name() string { return "WHOIS" }

func (e *WHOIS) Enrich(ctx context.Context, ip string) models.EnrichResult {
	fn := e.query
	if fn == nil {
		fn = func(host string) (string, error) {
			return gowhois.Whois(host)
		}
	}
	text, err := fn(ip)
	if err != nil {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusError, Note: err.Error()}
	}
	data := parseWHOISText(text)
	if data.Org == "" && data.Netblock == "" {
		return models.EnrichResult{Tool: e.Name(), Status: models.StatusNoData}
	}
	return models.EnrichResult{Tool: e.Name(), Status: models.StatusOK, Data: data}
}

func parseWHOISText(text string) models.WHOISResult {
	result := models.WHOISResult{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		val := extractWHOISValue(line)
		switch {
		case strings.HasPrefix(lower, "inetnum:") || strings.HasPrefix(lower, "netrange:") || strings.HasPrefix(lower, "cidr:"):
			if result.Netblock == "" {
				result.Netblock = val
			}
		case strings.HasPrefix(lower, "org-name:") || strings.HasPrefix(lower, "orgname:") || strings.HasPrefix(lower, "owner:"):
			if result.Org == "" {
				result.Org = val
			}
		case strings.Contains(lower, "abuse") && strings.Contains(lower, "mail"):
			if result.AbuseEmail == "" {
				result.AbuseEmail = val
			}
		case strings.HasPrefix(lower, "regdate:") || strings.HasPrefix(lower, "created:"):
			if result.Registered == "" {
				result.Registered = val
			}
		}
	}
	return result
}

func extractWHOISValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
