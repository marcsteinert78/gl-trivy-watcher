package main

import (
	"sync"
	"time"
)

// NamespaceState tracks the state of vulnerability reports for a namespace.
type NamespaceState struct {
	Hash            string
	StableSince     time.Time
	LastTriggerHash string
	LastTriggerTime time.Time
}

// NamespaceTracker manages state for all namespaces.
type NamespaceTracker struct {
	mu     sync.RWMutex
	states map[string]*NamespaceState
}

// NewNamespaceTracker creates a new tracker.
func NewNamespaceTracker() *NamespaceTracker {
	return &NamespaceTracker{
		states: make(map[string]*NamespaceState),
	}
}

// GetState returns the state for a namespace, creating if needed.
func (t *NamespaceTracker) GetState(namespace string) *NamespaceState {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, ok := t.states[namespace]
	if !ok {
		state = &NamespaceState{}
		t.states[namespace] = state
	}
	return state
}

// UpdateHash updates the hash for a namespace and returns whether it changed.
func (t *NamespaceTracker) UpdateHash(namespace, hash string) (changed bool, oldHash string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, ok := t.states[namespace]
	if !ok {
		state = &NamespaceState{}
		t.states[namespace] = state
	}

	oldHash = state.Hash
	if state.Hash != hash {
		state.Hash = hash
		state.StableSince = time.Now()
		return true, oldHash
	}
	return false, oldHash
}

// MarkTriggered records that a pipeline was triggered for the given hash.
func (t *NamespaceTracker) MarkTriggered(namespace, hash string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if state, ok := t.states[namespace]; ok {
		state.LastTriggerHash = hash
		state.LastTriggerTime = time.Now()
	}
}

// MarkAttempted records that an upload attempt was made without committing
// to a hash. Used after partial failures so the rate-limit (MinTriggerGap)
// still applies and the watcher doesn't hammer GitLab on a persistent error,
// while leaving LastTriggerHash untouched so the next cycle still retries.
func (t *NamespaceTracker) MarkAttempted(namespace string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if state, ok := t.states[namespace]; ok {
		state.LastTriggerTime = time.Now()
	}
}
