package session

import (
	"sync"
	"testing"
	"time"
)

// ──────────────────────────────────────────────
//  Session lifecycle tests
// ──────────────────────────────────────────────

func TestNewSession(t *testing.T) {
	s := NewSession("10.13.37.10:54321", 30, 20)

	if s.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if s.GetState() != StateInit {
		t.Errorf("expected INIT state, got %s", s.GetState())
	}
	if s.RemoteAddr != "10.13.37.10:54321" {
		t.Errorf("remote addr: got %s", s.RemoteAddr)
	}
	if s.BeaconInterval != 30 {
		t.Errorf("beacon interval: got %d", s.BeaconInterval)
	}
	if s.Jitter != 20 {
		t.Errorf("jitter: got %d", s.Jitter)
	}
	if s.TaskQueue == nil {
		t.Error("expected non-nil task queue")
	}
}

func TestValidTransitions(t *testing.T) {
	s := NewSession("127.0.0.1:1234", 30, 20)

	// INIT → REGISTERED
	if err := s.Transition(StateRegistered); err != nil {
		t.Fatalf("INIT → REGISTERED failed: %v", err)
	}
	if s.GetState() != StateRegistered {
		t.Errorf("expected REGISTERED, got %s", s.GetState())
	}

	// REGISTERED → ACTIVE
	if err := s.Transition(StateActive); err != nil {
		t.Fatalf("REGISTERED → ACTIVE failed: %v", err)
	}
	if s.GetState() != StateActive {
		t.Errorf("expected ACTIVE, got %s", s.GetState())
	}

	// ACTIVE → SHUTDOWN
	if err := s.Transition(StateShutdown); err != nil {
		t.Fatalf("ACTIVE → SHUTDOWN failed: %v", err)
	}
	if s.GetState() != StateShutdown {
		t.Errorf("expected SHUTDOWN, got %s", s.GetState())
	}
}

func TestInvalidTransitions(t *testing.T) {
	s := NewSession("127.0.0.1:1234", 30, 20)

	// INIT → ACTIVE (skip REGISTERED — invalid)
	if err := s.Transition(StateActive); err == nil {
		t.Error("INIT → ACTIVE should fail")
	}

	// INIT → REGISTERED (valid)
	s.Transition(StateRegistered)

	// REGISTERED → INIT (backwards — invalid)
	if err := s.Transition(StateInit); err == nil {
		t.Error("REGISTERED → INIT should fail")
	}
}

func TestRegister(t *testing.T) {
	s := NewSession("10.13.37.10:54321", 30, 20)

	err := s.Register("lab-victim-01", "linux", "amd64", "Ubuntu 22.04", "root")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if s.GetState() != StateRegistered {
		t.Errorf("expected REGISTERED, got %s", s.GetState())
	}
	if s.Hostname != "lab-victim-01" {
		t.Errorf("hostname: got %q", s.Hostname)
	}
	if s.OS != "linux" {
		t.Errorf("os: got %q", s.OS)
	}
	if s.Arch != "amd64" {
		t.Errorf("arch: got %q", s.Arch)
	}
	if s.Username != "root" {
		t.Errorf("username: got %q", s.Username)
	}
	if s.RegisteredAt.IsZero() {
		t.Error("expected non-zero RegisteredAt")
	}
}

// ──────────────────────────────────────────────
//  Sequence number tests
// ──────────────────────────────────────────────

func TestValidateSeq(t *testing.T) {
	s := NewSession("127.0.0.1:1234", 30, 20)

	// First seq should be valid.
	if !s.ValidateSeq(1) {
		t.Error("seq=1 should be valid")
	}

	// Monotonically increasing.
	if !s.ValidateSeq(2) {
		t.Error("seq=2 should be valid")
	}
	if !s.ValidateSeq(5) {
		t.Error("seq=5 should be valid (gap ok)")
	}

	// Replay / equal — should fail.
	if s.ValidateSeq(5) {
		t.Error("seq=5 (replay) should fail")
	}
	if s.ValidateSeq(3) {
		t.Error("seq=3 (backwards) should fail")
	}
	if s.ValidateSeq(0) {
		t.Error("seq=0 should fail")
	}
}

func TestNextServerSeq(t *testing.T) {
	s := NewSession("127.0.0.1:1234", 30, 20)

	for i := uint32(1); i <= 5; i++ {
		got := s.NextServerSeq()
		if got != i {
			t.Errorf("NextServerSeq: got %d, want %d", got, i)
		}
	}
}

// ──────────────────────────────────────────────
//  Liveness tests
// ──────────────────────────────────────────────

func TestTouch(t *testing.T) {
	s := NewSession("127.0.0.1:1234", 30, 20)

	before := s.LastSeenTime()
	time.Sleep(10 * time.Millisecond)
	s.Touch()
	after := s.LastSeenTime()

	if !after.After(before) {
		t.Error("Touch should update LastSeen")
	}
}

func TestIsExpired(t *testing.T) {
	s := NewSession("127.0.0.1:1234", 1, 0) // 1s interval, 0% jitter

	if s.IsExpired() {
		t.Error("should not be expired immediately")
	}

	// Force LastSeen to the past.
	s.mu.Lock()
	s.LastSeen = time.Now().Add(-5 * time.Second) // > 3×1s
	s.mu.Unlock()

	if !s.IsExpired() {
		t.Error("should be expired after 5s (deadline = 3s)")
	}
}

// ──────────────────────────────────────────────
//  Shutdown tests
// ──────────────────────────────────────────────

func TestRequestShutdown(t *testing.T) {
	s := NewSession("127.0.0.1:1234", 30, 20)

	// Channel should not be closed initially.
	select {
	case <-s.ShutdownCh:
		t.Fatal("ShutdownCh should not be closed yet")
	default:
	}

	s.RequestShutdown()

	// Channel should be closed now.
	select {
	case <-s.ShutdownCh:
		// ok
	default:
		t.Fatal("ShutdownCh should be closed after RequestShutdown")
	}

	// Calling again should not panic.
	s.RequestShutdown()
}

// ──────────────────────────────────────────────
//  Results tests
// ──────────────────────────────────────────────

func TestResults(t *testing.T) {
	s := NewSession("127.0.0.1:1234", 30, 20)

	if len(s.GetResults()) != 0 {
		t.Error("expected 0 results initially")
	}

	s.AddResult(Result{
		TaskID: "task-1",
		Status: 0,
		Data:   []byte("root\n"),
	})
	s.AddResult(Result{
		TaskID: "task-2",
		Status: 1,
		Error:  "permission denied",
	})

	results := s.GetResults()
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].TaskID != "task-1" {
		t.Errorf("result 0 task ID: got %q", results[0].TaskID)
	}
	if string(results[1].Error) != "permission denied" {
		t.Errorf("result 1 error: got %q", results[1].Error)
	}
}

// ──────────────────────────────────────────────
//  Manager tests
// ──────────────────────────────────────────────

func TestManagerAddGetRemove(t *testing.T) {
	m := NewManager()

	s := NewSession("10.13.37.10:1111", 30, 20)
	m.Add(s)

	got := m.Get(s.ID)
	if got == nil {
		t.Fatal("expected to find session")
	}
	if got.ID != s.ID {
		t.Errorf("session ID mismatch")
	}

	if m.Count() != 1 {
		t.Errorf("count: got %d, want 1", m.Count())
	}

	m.Remove(s.ID)
	if m.Get(s.ID) != nil {
		t.Error("session should be removed")
	}
	if m.Count() != 0 {
		t.Errorf("count after remove: got %d, want 0", m.Count())
	}
}

func TestManagerAll(t *testing.T) {
	m := NewManager()

	s1 := NewSession("10.13.37.10:1111", 30, 20)
	s2 := NewSession("10.13.37.20:2222", 30, 20)
	m.Add(s1)
	m.Add(s2)

	all := m.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(all))
	}
}

func TestManagerActive(t *testing.T) {
	m := NewManager()

	s1 := NewSession("10.13.37.10:1111", 30, 20)
	s1.Transition(StateRegistered)
	s1.Transition(StateActive)

	s2 := NewSession("10.13.37.20:2222", 30, 20)
	s2.Transition(StateRegistered)
	// s2 stays in REGISTERED

	m.Add(s1)
	m.Add(s2)

	active := m.Active()
	if len(active) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(active))
	}
	if active[0].ID != s1.ID {
		t.Error("wrong active session")
	}
}

func TestManagerShutdownAll(t *testing.T) {
	m := NewManager()

	s1 := NewSession("10.13.37.10:1111", 30, 20)
	s1.Transition(StateRegistered)
	s1.Transition(StateActive)

	s2 := NewSession("10.13.37.20:2222", 30, 20)
	s2.Transition(StateRegistered)
	s2.Transition(StateActive)

	s3 := NewSession("10.13.37.30:3333", 30, 20)
	s3.Transition(StateShutdown) // already shutdown

	m.Add(s1)
	m.Add(s2)
	m.Add(s3)

	count := m.ShutdownAll()
	if count != 2 {
		t.Errorf("expected 2 sessions notified, got %d", count)
	}

	// Verify channels are closed.
	select {
	case <-s1.ShutdownCh:
	default:
		t.Error("s1 should be shut down")
	}
	select {
	case <-s2.ShutdownCh:
	default:
		t.Error("s2 should be shut down")
	}
}

func TestManagerConcurrent(t *testing.T) {
	m := NewManager()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := NewSession("127.0.0.1:0", 30, 20)
			m.Add(s)
			m.Get(s.ID)
			m.All()
			m.Count()
			m.Remove(s.ID)
		}()
	}
	wg.Wait()
}

// ──────────────────────────────────────────────
//  State stringer
// ──────────────────────────────────────────────

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		str   string
	}{
		{StateInit, "INIT"},
		{StateRegistered, "REGISTERED"},
		{StateActive, "ACTIVE"},
		{StateShutdown, "SHUTDOWN"},
		{State(99), "UNKNOWN(99)"},
	}

	for _, tc := range tests {
		if got := tc.state.String(); got != tc.str {
			t.Errorf("State(%d).String() = %q, want %q", int(tc.state), got, tc.str)
		}
	}
}
