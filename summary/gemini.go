package summary

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ip-investigator/models"
)

type Gemini struct {
	Key     string
	baseURL string        // override in tests
	timeout time.Duration // override in tests
}

// Summarize sends all enricher results to Gemini and returns the AI assessment text.
func (g *Gemini) Summarize(ctx context.Context, ip string, results []models.EnrichResult) (string, error) {
	if g.Key == "" {
		return "", errors.New("no Gemini API key")
	}
	base := g.baseURL
	if base == "" {
		base = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent"
	}
	timeout := g.timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	prompt := buildPrompt(ip, results)
	reqBody, _ := json.Marshal(map[string]any{
		"contents": []map[string]any{
			{"parts": []map[string]any{{"text": prompt}}},
		},
	})

	url := fmt.Sprintf("%s?key=%s", base, g.Key)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("gemini HTTP %d", resp.StatusCode)
	}

	var body struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}
	if len(body.Candidates) == 0 || len(body.Candidates[0].Content.Parts) == 0 {
		return "", errors.New("empty response from Gemini")
	}
	return body.Candidates[0].Content.Parts[0].Text, nil
}

func buildPrompt(ip string, results []models.EnrichResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("You are a SOC L1 analyst assistant. Analyze the following threat intelligence data for IP %s.\n\n", ip))
	sb.WriteString("DATA SOURCES (status icons: ✅=ok ⚠️=partial ❌=no data 🚫=error):\n\n")

	for _, r := range results {
		sb.WriteString(fmt.Sprintf("[%s] %s\n", r.Status.Icon(), r.Tool))
		if r.Note != "" {
			sb.WriteString(fmt.Sprintf("  Note: %s\n", r.Note))
		}
		if r.Data != nil {
			dataJSON, _ := json.MarshalIndent(r.Data, "  ", "  ")
			sb.WriteString(fmt.Sprintf("  Data: %s\n", string(dataJSON)))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(`Provide a structured assessment with exactly these sections:
  Risk Level: [CRITICAL / HIGH / MEDIUM / LOW / CLEAN]
  Confidence: [High/Medium/Low] (X%)
  IOC Tags: [comma-separated tags]

  Key Findings (one bullet per tool with data):
  • [Tool] finding

  Overall Assessment:
  2-3 sentences. Mention any ⚠️/❌/🚫 tools and how gaps affect confidence.

  Recommended Action:
  Actionable steps for SOC L1.
`)
	return sb.String()
}
