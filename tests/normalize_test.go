package tests

import (
	"testing"

	"nvme-guard/internal/events"
)

func TestNormalizeDefaults(t *testing.T) {
	e := events.Event{}
	e = events.Normalize(e)
	if e.Severity != events.SeverityInfo {
		t.Fatalf("expected severity info, got %s", e.Severity)
	}
	if e.Action != events.ActionObserve {
		t.Fatalf("expected action observe, got %s", e.Action)
	}
}
