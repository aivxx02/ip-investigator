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

type OpenRouter struct {
	Key     string
	Model   string
	baseURL string
	timeout time.Duration
}

func (o *OpenRouter) Summarize(ctx context.Context, ip string, results []models.EnrichResult) (string, error) {
	if o.Key == "" {
		return "", errors.New("no OpenRouter API key")
	}
	base := o.baseURL
	if base == "" {
		base = "https://openrouter.ai/api/v1/chat/completions"
	}
	model := o.Model
	if model == "" {
		model = "google/gemma-2-9b-it:free"
	}

	prompt := buildPrompt(ip, results)
	reqBody, _ := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	})

	clientTimeout := o.timeout // 0 = rely on context; set in tests only
	client := &http.Client{Timeout: clientTimeout}
	req, err := http.NewRequestWithContext(ctx, "POST", base, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+o.Key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("openrouter request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var errBody struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error.Message != "" {
			return "", fmt.Errorf("openrouter HTTP %d: %s", resp.StatusCode, errBody.Error.Message)
		}
		return "", fmt.Errorf("openrouter HTTP %d", resp.StatusCode)
	}

	var body struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}
	if len(body.Choices) == 0 || body.Choices[0].Message.Content == "" {
		return "", errors.New("empty response from OpenRouter")
	}

	return body.Choices[0].Message.Content, nil
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
