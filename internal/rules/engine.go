package rules

import (
	"time"

	"nvme-guard/internal/events"
)

type Decision struct {
	MatchedRuleID string
	Severity      events.Severity
	Action        events.Action
	Reason        string
	Score         int
}

func Evaluate(rs RuleSet, e events.Event) Decision {
	d := Decision{
		MatchedRuleID: "",
		Severity:      e.Severity,
		Action:        e.Action,
		Reason:        e.Reason,
		Score:         0,
	}

	for _, rule := range rs.Rules {
		if !matches(rule.When, e) {
			continue
		}

		if d.MatchedRuleID == "" {
			d.MatchedRuleID = rule.ID
		}
		d.Score += rule.Then.ScoreDelta

		if rule.Then.Severity != "" {
			d.Severity = maxSeverity(d.Severity, rule.Then.Severity)
		}
		if rule.Then.Action != "" {
			d.Action = maxAction(d.Action, rule.Then.Action)
		}
		if rule.Then.MessageTmpl != "" {
			d.Reason = rule.Then.MessageTmpl
		}
	}

	return d
}

func matches(c Condition, e events.Event) bool {
	if len(c.SensorIs) > 0 && !sensorIn(c.SensorIs, e.Sensor) {
		return false
	}
	if len(c.IoctlRequestIn) > 0 && !u64In(c.IoctlRequestIn, e.Op.Request) {
		return false
	}
	if len(c.NVMeOpcodeIn) > 0 && !u8In(c.NVMeOpcodeIn, e.Op.NVMeOpcode) {
		return false
	}
	if len(c.VFSOpIn) > 0 && !vfsOpIn(c.VFSOpIn, e.Op.VFSOp) {
		return false
	}
	if len(c.BlockOpIn) > 0 && !blockOpIn(c.BlockOpIn, e.Op.BlockOp) {
		return false
	}
	if len(c.FilePathPrefix) > 0 && !prefixIn(c.FilePathPrefix, e.Target.FilePath) {
		return false
	}
	if len(c.DevicePathPrefix) > 0 && !prefixIn(c.DevicePathPrefix, e.Target.DevPath) {
		return false
	}
	if len(c.UIDIn) > 0 && !intIn(c.UIDIn, e.Proc.UID) {
		return false
	}
	if len(c.CommIn) > 0 && !stringIn(c.CommIn, e.Proc.Comm) {
		return false
	}
	if len(c.ExePathIn) > 0 && !stringIn(c.ExePathIn, e.Proc.ExePath) {
		return false
	}
	if len(c.ExeSHA256In) > 0 && !stringIn(c.ExeSHA256In, e.Proc.ExeSHA256) {
		return false
	}
	if len(c.CgroupPathContains) > 0 && !containsIn(c.CgroupPathContains, e.Proc.CgroupPath) {
		return false
	}
	if c.IsInteractiveTTY != nil && e.Proc.TTY != *c.IsInteractiveTTY {
		return false
	}
	if c.NotInMaintenanceWindow && InMaintenanceWindow(timeNow()) {
		return false
	}
	return true
}

func maxSeverity(a, b events.Severity) events.Severity {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

func maxAction(a, b events.Action) events.Action {
	if actionRank(b) > actionRank(a) {
		return b
	}
	return a
}

func severityRank(s events.Severity) int {
	switch s {
	case events.SeverityCritical:
		return 5
	case events.SeverityHigh:
		return 4
	case events.SeverityMedium:
		return 3
	case events.SeverityLow:
		return 2
	case events.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func actionRank(a events.Action) int {
	switch a {
	case events.ActionBlock:
		return 4
	case events.ActionWouldBlock:
		return 3
	case events.ActionAlert:
		return 2
	case events.ActionObserve:
		return 1
	default:
		return 0
	}
}

func sensorIn(list []events.Sensor, v events.Sensor) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func vfsOpIn(list []events.VFSOp, v events.VFSOp) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func blockOpIn(list []events.BlockOp, v events.BlockOp) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func u64In(list []uint64, v uint64) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func u8In(list []uint8, v uint8) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func intIn(list []int, v int) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func stringIn(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func prefixIn(prefixes []string, v string) bool {
	for _, p := range prefixes {
		if len(p) > 0 && len(v) >= len(p) && v[:len(p)] == p {
			return true
		}
	}
	return false
}

func containsIn(parts []string, v string) bool {
	for _, p := range parts {
		if p != "" && contains(v, p) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(substr) == 0 || indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}

func timeNow() time.Time {
	return time.Now()
}
