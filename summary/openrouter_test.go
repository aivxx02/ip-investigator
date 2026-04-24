package summary

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ip-investigator/models"
)

func TestOpenRouter_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"content": "Risk Level: CRITICAL\nRecommended Action: Block immediately",
					},
				},
			},
		})
	}))
	defer srv.Close()

	results := []models.EnrichResult{
		{Tool: "VirusTotal", Status: models.StatusOK, Data: models.VirusTotalResult{Detections: 12, Total: 94}},
		{Tool: "AbuseIPDB", Status: models.StatusPartial, Note: "daily limit reached"},
	}

	o := &OpenRouter{Key: "testkey", baseURL: srv.URL}
	text, err := o.Summarize(context.Background(), "185.220.101.45", results)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "CRITICAL") {
		t.Errorf("expected CRITICAL in summary, got: %s", text)
	}
}

func TestOpenRouter_NoKey(t *testing.T) {
	o := &OpenRouter{Key: ""}
	_, err := o.Summarize(context.Background(), "1.2.3.4", nil)
	if err == nil {
		t.Error("expected error when no API key")
	}
}

func TestOpenRouter_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	o := &OpenRouter{Key: "testkey", baseURL: srv.URL}
	_, err := o.Summarize(context.Background(), "1.2.3.4", nil)
	if err == nil {
		t.Error("expected error on HTTP 500")
	}
}
