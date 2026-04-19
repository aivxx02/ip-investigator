package models

import "testing"

func TestStatusIcon(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{StatusOK, "✅"},
		{StatusPartial, "⚠️"},
		{StatusNoData, "❌"},
		{StatusError, "🚫"},
	}
	for _, tt := range tests {
		got := tt.status.Icon()
		if got != tt.want {
			t.Errorf("Status(%d).Icon() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestParseOrg(t *testing.T) {
	asn, isp := ParseOrg("AS23764 Frantech Solutions")
	if asn != "AS23764" {
		t.Errorf("ASN = %q, want AS23764", asn)
	}
	if isp != "Frantech Solutions" {
		t.Errorf("ISP = %q, want Frantech Solutions", isp)
	}
}

func TestParseOrgNoSpace(t *testing.T) {
	asn, isp := ParseOrg("AS12345")
	if asn != "AS12345" || isp != "AS12345" {
		t.Errorf("ParseOrg(no space) = (%q, %q)", asn, isp)
	}
}
