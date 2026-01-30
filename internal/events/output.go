package events

import (
	"encoding/json"
	"io"
	"sync"
)

// JSONLOutput writes one JSON event per line.
type JSONLOutput struct {
	enc *json.Encoder
	mu  sync.Mutex
}

func NewJSONLOutput(w io.Writer) *JSONLOutput {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONLOutput{enc: enc}
}

func (o *JSONLOutput) WriteEvent(e Event) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.enc.Encode(e)
}
