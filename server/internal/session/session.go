// Package session manages agent sessions for the Team Server.
//
// Each agent connection creates a Session object that tracks its lifecycle
// state, sequence numbers, and provides a task queue for pending work.
// The Manager is the central registry of all sessions, safe for concurrent
// use from the TLS listener goroutines and gRPC API goroutines.
//
// ACADEMIC/EDUCATIONAL USE ONLY.
package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/c2-framework/server/internal/taskqueue"
)

// ──────────────────────────────────────────────
//  Session states
// ──────────────────────────────────────────────

// State represents the lifecycle state of a session.
type State int

const (
	StateInit       State = 0 // TLS connection established, awaiting REGISTER
	StateRegistered State = 1 // REGISTER received, awaiting first BEACON
	StateActive     State = 2 // Normal operation (BEACON / TASK / RESULT)
	StateShutdown   State = 3 // Terminal state
)

// String returns a human-readable state name.
func (s State) String() string {
	switch s {
	case StateInit:
		return "INIT"
	case StateRegistered:
		return "REGISTERED"
	case StateActive:
		return "ACTIVE"
	case StateShutdown:
		return "SHUTDOWN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// ──────────────────────────────────────────────
//  Session
// ──────────────────────────────────────────────

// Session represents a single agent connection.
type Session struct {
	mu sync.RWMutex

	// Identity
	ID         string // UUID v4 (hex string)
	Hostname   string
	OS         string
	Arch       string
	OSVersion  string
	Username   string
	RemoteAddr string // IP:port of the agent

	// State machine
	State State

	// Timing
	RegisteredAt time.Time
	LastSeen     time.Time

	// Beacon configuration
	BeaconInterval uint32 // seconds
	Jitter         uint8  // percentage 0–100

	// Sequence tracking
	LastSeqNumber uint32 // Last sequence number received from agent
	ServerSeq     uint32 // Server-side sequence counter

	// Task management
	TaskQueue *taskqueue.Queue

	// Results collected from this session
	Results []Result

	// Shutdown signal channel — closed when a shutdown is requested
	ShutdownCh chan struct{}
	shutOnce   sync.Once
}

// Result stores a task execution result from the agent.
type Result struct {
	TaskID     string
	Status     uint8 // 0=success, 1=error, 2=timeout
	Data       []byte
	Error      string
	ElapsedMs  uint32
	ReceivedAt time.Time
}

// NewSession creates a new session in INIT state with a unique ID.
func NewSession(remoteAddr string, beaconInterval uint32, jitter uint8) *Session {
	return &Session{
		ID:             uuid.New().String(),
		State:          StateInit,
		RemoteAddr:     remoteAddr,
		BeaconInterval: beaconInterval,
		Jitter:         jitter,
		LastSeen:       time.Now(),
		TaskQueue:      taskqueue.New(),
		ShutdownCh:     make(chan struct{}),
	}
}

// ──────────────────────────────────────────────
//  State transitions
// ──────────────────────────────────────────────

// Transition attempts a state transition. Returns an error if the
// transition is invalid.
func (s *Session) Transition(newState State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !validTransition(s.State, newState) {
		return fmt.Errorf("session %s: invalid transition %s → %s",
			s.ID, s.State, newState)
	}

	s.State = newState
	return nil
}

// validTransition checks whether a state transition is allowed.
func validTransition(from, to State) bool {
	// Any state can transition to SHUTDOWN.
	if to == StateShutdown {
		return true
	}

	switch from {
	case StateInit:
		return to == StateRegistered
	case StateRegistered:
		return to == StateActive
	case StateActive:
		return to == StateActive // self-loop for normal operations
	default:
		return false
	}
}

// GetState returns the current session state.
func (s *Session) GetState() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}

// ──────────────────────────────────────────────
//  Sequence number validation
// ──────────────────────────────────────────────

// ValidateSeq checks that the given sequence number is strictly greater
// than the last seen sequence number. If valid, it updates LastSeqNumber
// and returns true. Otherwise returns false.
func (s *Session) ValidateSeq(seq uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if seq <= s.LastSeqNumber {
		return false
	}

	s.LastSeqNumber = seq
	return true
}

// NextServerSeq increments and returns the next server-side sequence number.
func (s *Session) NextServerSeq() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ServerSeq++
	return s.ServerSeq
}

// ──────────────────────────────────────────────
//  Registration
// ──────────────────────────────────────────────

// Register populates the session with agent information from the
// REGISTER message and transitions to REGISTERED state.
func (s *Session) Register(hostname, os, arch, osVersion, username string) error {
	s.mu.Lock()
	s.Hostname = hostname
	s.OS = os
	s.Arch = arch
	s.OSVersion = osVersion
	s.Username = username
	s.RegisteredAt = time.Now()
	s.LastSeen = time.Now()
	s.mu.Unlock()

	return s.Transition(StateRegistered)
}

// ──────────────────────────────────────────────
//  Touch / liveness
// ──────────────────────────────────────────────

// Touch updates the LastSeen timestamp.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSeen = time.Now()
}

// LastSeenTime returns the last-seen timestamp.
func (s *Session) LastSeenTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastSeen
}

// IsExpired returns true if no beacon has been received within
// the deadline (3× beacon interval).
func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	deadline := time.Duration(s.BeaconInterval) * 3 * time.Second
	return time.Since(s.LastSeen) > deadline
}

// ──────────────────────────────────────────────
//  Shutdown
// ──────────────────────────────────────────────

// RequestShutdown signals the session to shut down. Safe to call
// multiple times.
func (s *Session) RequestShutdown() {
	s.shutOnce.Do(func() {
		close(s.ShutdownCh)
	})
}

// ──────────────────────────────────────────────
//  Results
// ──────────────────────────────────────────────

// AddResult stores a task result.
func (s *Session) AddResult(r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Results = append(s.Results, r)
}

// GetResults returns a copy of all collected results.
func (s *Session) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Result, len(s.Results))
	copy(out, s.Results)
	return out
}

// ──────────────────────────────────────────────
//  Manager — central session registry
// ──────────────────────────────────────────────

// Manager maintains a registry of all sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by session ID
}

// NewManager creates a new empty session manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
	}
}

// Add registers a session in the manager.
func (m *Manager) Add(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
}

// Get retrieves a session by ID. Returns nil if not found.
func (m *Manager) Get(id string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// Remove deletes a session from the manager.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// All returns a snapshot of all sessions.
func (m *Manager) All() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// Active returns all sessions in ACTIVE state.
func (m *Manager) Active() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*Session
	for _, s := range m.sessions {
		if s.GetState() == StateActive {
			out = append(out, s)
		}
	}
	return out
}

// Count returns the total number of tracked sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// ShutdownAll requests shutdown for every active session and returns
// the number of sessions notified.
func (m *Manager) ShutdownAll() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, s := range m.sessions {
		if s.GetState() == StateActive || s.GetState() == StateRegistered {
			s.RequestShutdown()
			count++
		}
	}
	return count
}
