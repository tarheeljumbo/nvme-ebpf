package tests

import (
	"testing"

	"nvme-guard/internal/events"
	"nvme-guard/internal/rules"
)

func TestRuleMatchesSensorAndVFSOp(t *testing.T) {
	ruleset := rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID: "boot-write",
				When: rules.Condition{
					SensorIs: []events.Sensor{events.SensorBootVFS},
					VFSOpIn:  []events.VFSOp{events.VFSWrite},
				},
				Then: rules.Action{
					Severity:   events.SeverityHigh,
					Action:     events.ActionAlert,
					MessageTmpl: "boot write",
				},
			},
		},
	}

	e := events.Event{
		Sensor: events.SensorBootVFS,
		Op: events.OpCtx{
			VFSOp: events.VFSWrite,
		},
	}

	d := rules.Evaluate(ruleset, e)
	if d.Severity != events.SeverityHigh {
		t.Fatalf("expected severity high, got %s", d.Severity)
	}
	if d.Action != events.ActionAlert {
		t.Fatalf("expected action alert, got %s", d.Action)
	}
	if d.Reason != "boot write" {
		t.Fatalf("expected reason set, got %q", d.Reason)
	}
}

func TestRulePrefixMatch(t *testing.T) {
	ruleset := rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID: "boot-prefix",
				When: rules.Condition{
					FilePathPrefix: []string{"/boot"},
				},
				Then: rules.Action{
					Severity: events.SeverityMedium,
					Action:   events.ActionAlert,
				},
			},
		},
	}

	e := events.Event{
		Target: events.TargetCtx{FilePath: "/boot/vmlinuz"},
	}

	d := rules.Evaluate(ruleset, e)
	if d.Severity != events.SeverityMedium {
		t.Fatalf("expected severity medium, got %s", d.Severity)
	}
	if d.Action != events.ActionAlert {
		t.Fatalf("expected action alert, got %s", d.Action)
	}
}

func TestRuleDoesNotMatch(t *testing.T) {
	ruleset := rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID: "nvme-only",
				When: rules.Condition{
					SensorIs: []events.Sensor{events.SensorNVMeIOCTL},
				},
				Then: rules.Action{
					Severity: events.SeverityCritical,
					Action:   events.ActionBlock,
				},
			},
		},
	}

	e := events.Event{Sensor: events.SensorBootVFS}
	d := rules.Evaluate(ruleset, e)
	if d.MatchedRuleID != "" {
		t.Fatalf("expected no rule match, got %s", d.MatchedRuleID)
	}
	if d.Action != "" || d.Severity != "" {
		t.Fatalf("expected no decision override")
	}
}

func TestRuleUIDCommExeCgroupMatches(t *testing.T) {
	ruleset := rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID: "proc-match",
				When: rules.Condition{
					UIDIn:               []int{0, 1000},
					CommIn:              []string{"bash"},
					ExePathIn:           []string{"/usr/bin/bash"},
					ExeSHA256In:         []string{"deadbeef"},
					CgroupPathContains:  []string{"docker"},
					IsInteractiveTTY:    boolPtr(true),
				},
				Then: rules.Action{
					Severity: events.SeverityLow,
					Action:   events.ActionAlert,
				},
			},
		},
	}

	e := events.Event{
		Proc: events.ProcCtx{
			UID:          0,
			Comm:         "bash",
			ExePath:      "/usr/bin/bash",
			ExeSHA256:    "deadbeef",
			CgroupPath:   "/sys/fs/cgroup/docker/123",
			TTY:          true,
		},
	}

	d := rules.Evaluate(ruleset, e)
	if d.Severity != events.SeverityLow {
		t.Fatalf("expected severity low, got %s", d.Severity)
	}
	if d.Action != events.ActionAlert {
		t.Fatalf("expected action alert, got %s", d.Action)
	}
}

func TestRuleScoreAccumulationAndRanking(t *testing.T) {
	ruleset := rules.RuleSet{
		Rules: []rules.Rule{
			{
				ID: "base",
				When: rules.Condition{
					SensorIs: []events.Sensor{events.SensorNVMeIOCTL},
				},
				Then: rules.Action{
					Severity:   events.SeverityLow,
					ScoreDelta: 1,
					Action:     events.ActionAlert,
				},
			},
			{
				ID: "elevate",
				When: rules.Condition{
					SensorIs: []events.Sensor{events.SensorNVMeIOCTL},
				},
				Then: rules.Action{
					Severity:   events.SeverityHigh,
					ScoreDelta: 5,
					Action:     events.ActionWouldBlock,
				},
			},
		},
	}

	e := events.Event{Sensor: events.SensorNVMeIOCTL}
	d := rules.Evaluate(ruleset, e)
	if d.Score != 6 {
		t.Fatalf("expected score 6, got %d", d.Score)
	}
	if d.Severity != events.SeverityHigh {
		t.Fatalf("expected severity high, got %s", d.Severity)
	}
	if d.Action != events.ActionWouldBlock {
		t.Fatalf("expected action would_block, got %s", d.Action)
	}
}

func boolPtr(v bool) *bool {
	return &v
}
