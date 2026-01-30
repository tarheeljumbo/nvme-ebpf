package rules

import "time"

// InMaintenanceWindow is a stub until maintenance windows are parsed.
func InMaintenanceWindow(_ time.Time) bool {
	return false
}
