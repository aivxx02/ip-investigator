package enrichers

import (
	"context"
	"fmt"
	"testing"

	"ip-investigator/models"
)

const sampleWHOIS = `
inetnum:        185.220.100.0 - 185.220.103.255
netname:        FRANTECH
org-name:       Frantech Solutions
abuse-mailbox:  abuse@frantech.ca
created:        2018-03-12
`

func TestWHOIS_Parse(t *testing.T) {
	e := &WHOIS{
		query: func(host string) (string, error) {
			return sampleWHOIS, nil
		},
	}
	result := e.Enrich(context.Background(), "185.220.101.45")
	if result.Status != models.StatusOK {
		t.Fatalf("status = %v, want StatusOK", result.Status)
	}
	data := result.Data.(models.WHOISResult)
	if data.Org != "Frantech Solutions" {
		t.Errorf("Org = %q, want Frantech Solutions", data.Org)
	}
	if data.AbuseEmail != "abuse@frantech.ca" {
		t.Errorf("AbuseEmail = %q, want abuse@frantech.ca", data.AbuseEmail)
	}
	if data.Netblock == "" {
		t.Error("Netblock should not be empty")
	}
	if data.Registered == "" {
		t.Error("Registered should not be empty")
	}
}

func TestWHOIS_NoData(t *testing.T) {
	e := &WHOIS{
		query: func(host string) (string, error) {
			return "% No data found", nil
		},
	}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusNoData {
		t.Errorf("expected StatusNoData, got %v", result.Status)
	}
}

func TestWHOIS_Error(t *testing.T) {
	e := &WHOIS{
		query: func(host string) (string, error) {
			return "", fmt.Errorf("connection refused")
		},
	}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusError {
		t.Errorf("expected StatusError, got %v", result.Status)
	}
}
