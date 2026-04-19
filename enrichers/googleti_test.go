package enrichers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ip-investigator/models"
)

func TestGoogleTI_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"attributes": map[string]any{
					"threat_severity": map[string]any{
						"level_description": "CRITICAL",
					},
					"crowdsourced_context": []map[string]any{
						{"title": "APT-12345"},
					},
				},
			},
		})
	}))
	defer srv.Close()

	e := &GoogleTI{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "185.220.101.45")

	if result.Status != models.StatusOK {
		t.Fatalf("status = %v, want StatusOK", result.Status)
	}
	data := result.Data.(models.GoogleTIResult)
	if data.Verdict != "CRITICAL" {
		t.Errorf("Verdict = %q, want CRITICAL", data.Verdict)
	}
	if data.Actor != "APT-12345" {
		t.Errorf("Actor = %q, want APT-12345", data.Actor)
	}
}

func TestGoogleTI_NoKey(t *testing.T) {
	e := &GoogleTI{Key: ""}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusError {
		t.Errorf("expected StatusError, got %v", result.Status)
	}
}

func TestGoogleTI_NoData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"attributes": map[string]any{
					"threat_severity":      map[string]any{"level_description": ""},
					"crowdsourced_context": []any{},
				},
			},
		})
	}))
	defer srv.Close()

	e := &GoogleTI{Key: "testkey", baseURL: srv.URL}
	result := e.Enrich(context.Background(), "1.2.3.4")
	if result.Status != models.StatusNoData {
		t.Errorf("expected StatusNoData, got %v", result.Status)
	}
}
