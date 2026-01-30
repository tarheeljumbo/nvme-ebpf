package events

// Normalize applies safe defaults to an Event.
func Normalize(e Event) Event {
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	if e.Action == "" {
		e.Action = ActionObserve
	}
	return e
}
