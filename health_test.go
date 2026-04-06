package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthFresh(t *testing.T) {
	h := NewHealth(1 * time.Second)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestHealthStale(t *testing.T) {
	h := NewHealth(10 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestHealthMarkPollResetsStaleness(t *testing.T) {
	h := NewHealth(50 * time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	h.MarkPoll()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 after MarkPoll", rec.Code)
	}
}
