package main

import (
	"fmt"
	"sync"
	"time"
)

// spinner characters for animation
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ProgressDisplay manages an animated progress display during wait periods.
type ProgressDisplay struct {
	mu       sync.Mutex
	active   bool
	stopCh   chan struct{}
	doneCh   chan struct{}
	message  string
	endTime  time.Time
	interval time.Duration
}

// NewProgressDisplay creates a new progress display with the given update interval.
func NewProgressDisplay(interval time.Duration) *ProgressDisplay {
	return &ProgressDisplay{
		interval: interval,
	}
}

// Start begins displaying progress with the given message until endTime.
func (p *ProgressDisplay) Start(message string, endTime time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Stop any existing display
	if p.active {
		close(p.stopCh)
		<-p.doneCh
	}

	p.active = true
	p.message = message
	p.endTime = endTime
	p.stopCh = make(chan struct{})
	p.doneCh = make(chan struct{})

	go p.run()
}

// Stop stops the progress display.
func (p *ProgressDisplay) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.active {
		close(p.stopCh)
		<-p.doneCh
		p.active = false
	}
}

// run is the goroutine that updates the display.
func (p *ProgressDisplay) run() {
	defer close(p.doneCh)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	frame := 0
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			remaining := time.Until(p.endTime)
			if remaining < 0 {
				remaining = 0
			}

			spinner := spinnerFrames[frame%len(spinnerFrames)]
			frame++

			// Format remaining time
			var timeStr string
			if remaining >= time.Minute {
				timeStr = fmt.Sprintf("%dm%02ds", int(remaining.Minutes()), int(remaining.Seconds())%60)
			} else {
				timeStr = fmt.Sprintf("%ds", int(remaining.Seconds()))
			}

			// Print on new line (works with kubectl logs)
			fmt.Printf("[%s] %s %s... %s remaining\n",
				time.Now().Format("15:04:05"), spinner, p.message, timeStr)
		}
	}
}
