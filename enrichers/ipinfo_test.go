package enrichers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ip-investigator/models"
)

func TestIPInfo_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"country": "DE",
			"city":    "Frankfurt",
			"org":     "AS23764 Frantech Solutions",
		})
	}))
	defer srv.Close()

	e := &IPInfo{baseURL: srv.URL}
	result := e.Enrich(context.Background(), "185.220.101.45")

	if result.Status != models.StatusOK {
		t.Fatalf("status = %v, want StatusOK", result.Status)
	}
	geo, ok := result.Data.(models.GeoResult)
	if !ok {
		t.Fatal("Data is not GeoResult")
	}
	if geo.Country != "DE" {
		t.Errorf("Country = %q, want DE", geo.Country)
	}
	if geo.ASN != "AS23764" {
		t.Errorf("ASN = %q, want AS23764", geo.ASN)
	}
	if geo.ISP != "Frantech Solutions" {
		t.Errorf("ISP = %q, want Frantech Solutions", geo.ISP)
	}
}

func TestIPInfo_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	e := &IPInfo{baseURL: srv.URL, timeout: 50 * time.Millisecond}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusError {
		t.Errorf("expected StatusError on timeout, got %v", result.Status)
	}
}
