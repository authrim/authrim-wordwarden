package auditlog

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/authrim/authrim-wordwarden/internal/core/audit"
)

type JSONSink struct {
	mu     sync.Mutex
	writer io.Writer
}

func NewJSONSink(writer io.Writer) *JSONSink {
	return &JSONSink{writer: writer}
}

func (s *JSONSink) WriteEvent(_ context.Context, event audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.NewEncoder(s.writer).Encode(event)
}
