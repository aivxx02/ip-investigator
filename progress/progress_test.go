package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"ip-investigator/models"
)

func TestBar_empty(t *testing.T) {
	b := greenBar(0, 10)
	plain := stripAnsi(b)
	if len([]rune(plain)) != 10 {
		t.Errorf("expected 10 runes, got %d: %q", len([]rune(plain)), plain)
	}
	if !strings.Contains(plain, "░") {
		t.Errorf("expected empty bar to contain ░")
	}
}

func TestBar_full(t *testing.T) {
	b := greenBar(1.0, 10)
	plain := stripAnsi(b)
	if !strings.Contains(plain, "█") {
		t.Errorf("expected full bar to contain █")
	}
	if strings.Contains(plain, "░") {
		t.Errorf("expected full bar to have no ░")
	}
}

func TestTracker_noPanic(t *testing.T) {
	var buf bytes.Buffer
	tr := New(&buf)
	tr.Start("1.2.3.4", []string{"ToolA", "ToolB"})
	tr.Complete(0, models.StatusOK, 100*time.Millisecond, "")
	tr.Complete(1, models.StatusError, 200*time.Millisecond, "")
	tr.StartAI()
	tr.DoneAI(500 * time.Millisecond)
	tr.Clear()
}

func TestTracker_clearErasesLines(t *testing.T) {
	var buf bytes.Buffer
	tr := New(&buf)
	tr.Start("8.8.8.8", []string{"X"})
	tr.Complete(0, models.StatusOK, 50*time.Millisecond, "")
	tr.Clear()

	out := buf.String()
	if !strings.Contains(out, "\033[") {
		t.Error("expected ANSI escape sequences in output")
	}
}

// stripAnsi removes ANSI color escape sequences for plain-text assertions.
func stripAnsi(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
