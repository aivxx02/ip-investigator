package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"ip-investigator/models"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type entry struct {
	name    string
	done    bool
	status  models.Status
	elapsed time.Duration
}

// Tracker renders a live per-tool progress display in-place using ANSI escape codes.
type Tracker struct {
	out         io.Writer
	ip          string
	mu          sync.Mutex
	tools       []entry
	doneCount   int
	startTime   time.Time
	frameIdx    int
	totalLines  int
	stop        chan struct{}
	spinnerDone chan struct{}
	aiVisible   bool
	aiDone      bool
	aiStart     time.Time
	aiElapsed   time.Duration
}

// New returns a Tracker that writes to out. Pass nil to use os.Stdout.
func New(out io.Writer) *Tracker {
	if out == nil {
		out = os.Stdout
	}
	return &Tracker{
		out:         out,
		stop:        make(chan struct{}),
		spinnerDone: make(chan struct{}),
	}
}

// Start prints the initial display and begins animating the spinner.
func (t *Tracker) Start(ip string, names []string) {
	t.ip = ip
	t.tools = make([]entry, len(names))
	for i, n := range names {
		t.tools[i] = entry{name: n}
	}
	t.startTime = time.Now()

	t.mu.Lock()
	t.redraw()
	t.mu.Unlock()

	go func() {
		defer close(t.spinnerDone)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-t.stop:
				return
			case <-ticker.C:
				t.mu.Lock()
				t.frameIdx = (t.frameIdx + 1) % len(frames)
				t.redraw()
				t.mu.Unlock()
			}
		}
	}()
}

// Complete marks the tool at idx as finished.
func (t *Tracker) Complete(idx int, status models.Status, elapsed time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tools[idx].done = true
	t.tools[idx].status = status
	t.tools[idx].elapsed = elapsed
	t.doneCount++
	t.redraw()
}

// StartAI switches display to the AI summary phase.
func (t *Tracker) StartAI() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.aiVisible = true
	t.aiStart = time.Now()
	t.redraw()
}

// DoneAI marks the AI summary as complete.
func (t *Tracker) DoneAI(elapsed time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.aiDone = true
	t.aiElapsed = elapsed
	t.redraw()
}

// Clear stops the spinner and erases all printed lines from the terminal.
func (t *Tracker) Clear() {
	close(t.stop)
	<-t.spinnerDone
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.totalLines > 0 {
		fmt.Fprintf(t.out, "\033[%dA", t.totalLines)
		for i := 0; i < t.totalLines; i++ {
			fmt.Fprintf(t.out, "\r\033[K\n")
		}
		fmt.Fprintf(t.out, "\033[%dA", t.totalLines)
	}
}

// redraw moves cursor to start of block and rewrites every line.
// Must be called with t.mu held.
func (t *Tracker) redraw() {
	if t.totalLines > 0 {
		fmt.Fprintf(t.out, "\033[%dA", t.totalLines)
	}

	lines := 0
	w := t.out

	// Header
	fmt.Fprintf(w, "\r\033[K\n")
	lines++
	fmt.Fprintf(w, "\r\033[K  Investigating %s...\n", color.CyanString(t.ip))
	lines++
	fmt.Fprintf(w, "\r\033[K\n")
	lines++

	// Tool rows
	for _, e := range t.tools {
		fmt.Fprintf(w, "\r\033[K")
		if e.done {
			t.writeToolDone(e)
		} else {
			fmt.Fprintf(w, "  %s  %s\n",
				color.YellowString(frames[t.frameIdx]),
				color.New(color.FgHiBlack).Sprint(e.name))
		}
		lines++
	}

	// Blank separator
	fmt.Fprintf(w, "\r\033[K\n")
	lines++

	// Enricher progress bar
	n := len(t.tools)
	pct := 0.0
	if n > 0 {
		pct = float64(t.doneCount) / float64(n)
	}
	fmt.Fprintf(w, "\r\033[K  %s  %s  %s  %s\n",
		color.New(color.FgCyan).Sprint("Enrichers "),
		greenBar(pct, 20),
		color.New(color.FgHiBlack).Sprintf("%d/%d", t.doneCount, n),
		color.CyanString(t.eta()))
	lines++

	// AI Summary progress bar
	if t.aiDone {
		fmt.Fprintf(w, "\r\033[K  %s  %s  %s\n",
			color.MagentaString("AI Summary"),
			magentaBar(1.0, 20),
			color.GreenString("done  "))
	} else if t.aiVisible {
		fmt.Fprintf(w, "\r\033[K  %s  %s  %s\n",
			color.MagentaString("AI Summary"),
			magentaBar(0.4, 20),
			color.MagentaString("running"))
	} else {
		fmt.Fprintf(w, "\r\033[K  %s  %s  %s\n",
			color.New(color.FgHiBlack).Sprint("AI Summary"),
			dimBar(0, 20),
			color.New(color.FgHiBlack).Sprint("waiting"))
	}
	lines++

	// AI spinner row (shown only while AI is running or done)
	if t.aiVisible {
		fmt.Fprintf(w, "\r\033[K")
		if t.aiDone {
			fmt.Fprintf(w, "  %s  %s  %s\n",
				color.GreenString("✓"),
				color.MagentaString("OpenRouter AI"),
				color.New(color.FgHiBlack).Sprintf("%.1fs", t.aiElapsed.Seconds()))
		} else {
			fmt.Fprintf(w, "  %s  %s  %s\n",
				color.MagentaString(frames[t.frameIdx]),
				color.MagentaString("OpenRouter AI"),
				color.New(color.FgHiBlack).Sprint("generating summary..."))
		}
		lines++
	}

	t.totalLines = lines
}

func (t *Tracker) writeToolDone(e entry) {
	timeStr := color.New(color.FgHiBlack).Sprintf("%.1fs", e.elapsed.Seconds())
	switch e.status {
	case models.StatusOK:
		fmt.Fprintf(t.out, "  %s  %-14s %s\n",
			color.GreenString("✓"), color.WhiteString(e.name), timeStr)
	case models.StatusPartial:
		fmt.Fprintf(t.out, "  %s  %-14s %s  %s\n",
			color.YellowString("⚠"), color.YellowString(e.name), timeStr,
			color.YellowString("rate limited"))
	case models.StatusNoData:
		fmt.Fprintf(t.out, "  %s  %-14s %s  %s\n",
			color.New(color.FgHiBlack).Sprint("—"),
			color.New(color.FgHiBlack).Sprint(e.name), timeStr,
			color.New(color.FgHiBlack).Sprint("no data"))
	default: // StatusError
		fmt.Fprintf(t.out, "  %s  %-14s %s\n",
			color.RedString("✗"), color.RedString(e.name), timeStr)
	}
}

func (t *Tracker) eta() string {
	if t.doneCount == 0 {
		return "ETA ~?s "
	}
	if t.doneCount == len(t.tools) {
		return "done    "
	}
	elapsed := time.Since(t.startTime)
	remaining := len(t.tools) - t.doneCount
	secs := int(float64(elapsed)/float64(t.doneCount)*float64(remaining)/float64(time.Second)) + 1
	return fmt.Sprintf("ETA ~%ds", secs)
}

func greenBar(pct float64, width int) string {
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	return color.GreenString(strings.Repeat("█", filled)) +
		color.New(color.FgHiBlack).Sprint(strings.Repeat("░", width-filled))
}

func magentaBar(pct float64, width int) string {
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	return color.MagentaString(strings.Repeat("█", filled)) +
		color.New(color.FgHiBlack).Sprint(strings.Repeat("░", width-filled))
}

func dimBar(pct float64, width int) string {
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	return color.New(color.FgHiBlack).Sprint(strings.Repeat("█", filled) + strings.Repeat("░", width-filled))
}
