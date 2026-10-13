// Package audit implements an append-only JSON-lines audit logger.
//
// Every significant event (task dispatch, session registration, disconnect,
// timeout) is written as a single JSON object on its own line, making the
// log easy to grep, tail, and ingest into SIEM tooling.
//
// The logger is safe for concurrent use from multiple goroutines.
//
// ACADEMIC/EDUCATIONAL USE ONLY.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
//  Event types
// ──────────────────────────────────────────────

// EventType categorises audit log entries.
type EventType string

const (
	EventSessionRegister   EventType = "session.register"
	EventSessionActive     EventType = "session.active"
	EventSessionDisconnect EventType = "session.disconnect"
	EventSessionTimeout    EventType = "session.timeout"
	EventSessionShutdown   EventType = "session.shutdown"
	EventTaskDispatched    EventType = "task.dispatched"
	EventTaskResult        EventType = "task.result"
	EventServerStart       EventType = "server.start"
	EventServerStop        EventType = "server.stop"
	EventBroadcastShutdown EventType = "broadcast.shutdown"
)

// ──────────────────────────────────────────────
//  Log entry
// ──────────────────────────────────────────────

// Entry represents a single audit log record.
type Entry struct {
	Timestamp string    `json:"timestamp"`           // RFC 3339 with nanoseconds
	Event     EventType `json:"event"`               // Event category
	SessionID string    `json:"session_id,omitempty"` // Associated session (if any)
	Operator  string    `json:"operator,omitempty"`   // Operator identity (if any)
	TaskType  string    `json:"task_type,omitempty"`  // Task type (for task events)
	TaskID    string    `json:"task_id,omitempty"`    // Server-assigned task ID
	Detail    string    `json:"detail,omitempty"`     // Human-readable detail
	Remote    string    `json:"remote,omitempty"`     // Remote address (for session events)
}

// ──────────────────────────────────────────────
//  Logger
// ──────────────────────────────────────────────

// Logger writes structured audit entries to an append-only file.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// New creates a new audit Logger writing to the given file path.
// The file is created if it does not exist, and opened in append mode.
func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}

	return &Logger{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

// Log writes a single audit entry with the current timestamp.
func (l *Logger) Log(entry Entry) error {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.enc.Encode(entry); err != nil {
		return fmt.Errorf("audit: encode: %w", err)
	}

	// Ensure durability — flush to disk after each entry.
	return l.file.Sync()
}

// Close flushes and closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// ──────────────────────────────────────────────
//  Convenience methods
// ──────────────────────────────────────────────

// SessionEvent logs a session lifecycle event.
func (l *Logger) SessionEvent(event EventType, sessionID, remote, detail string) error {
	return l.Log(Entry{
		Event:     event,
		SessionID: sessionID,
		Remote:    remote,
		Detail:    detail,
	})
}

// TaskEvent logs a task-related event.
func (l *Logger) TaskEvent(event EventType, sessionID, operator, taskType, taskID, detail string) error {
	return l.Log(Entry{
		Event:     event,
		SessionID: sessionID,
		Operator:  operator,
		TaskType:  taskType,
		TaskID:    taskID,
		Detail:    detail,
	})
}

// ServerEvent logs a server lifecycle event.
func (l *Logger) ServerEvent(event EventType, detail string) error {
	return l.Log(Entry{
		Event:  event,
		Detail: detail,
	})
}
