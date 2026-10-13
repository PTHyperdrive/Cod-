// Package listener implements the TLS listener that accepts agent
// connections and processes the Codé TLV wire protocol.
//
// Each accepted connection spawns a goroutine that:
//   1. Waits for a REGISTER message (10s timeout)
//   2. Creates a session and transitions to REGISTERED
//   3. Processes BEACON / RESULT messages in a loop
//   4. Dispatches queued TASK messages on each beacon
//   5. Handles SHUTDOWN gracefully
//
// ACADEMIC/EDUCATIONAL USE ONLY.
package listener

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/c2-framework/server/internal/audit"
	"github.com/c2-framework/server/internal/codec"
	"github.com/c2-framework/server/internal/session"
)

// ──────────────────────────────────────────────
//  Configuration
// ──────────────────────────────────────────────

// Config holds the listener configuration.
type Config struct {
	ListenAddr string // e.g. "10.13.37.1:443"

	// TLS
	CertFile string // Server certificate PEM
	KeyFile  string // Server private key PEM
	CAFile   string // CA certificate PEM (for reference, not mTLS here)

	// Defaults
	DefaultBeaconInterval uint32 // seconds (sent to agents in REGISTER response)
	DefaultJitter         uint8  // percentage 0–100

	// Timeouts
	RegisterTimeout  time.Duration // max wait for REGISTER after TLS handshake
	FirstBeaconWait  time.Duration // max wait for first BEACON after REGISTERED
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:            "0.0.0.0:443",
		DefaultBeaconInterval: 30,
		DefaultJitter:         20,
		RegisterTimeout:       10 * time.Second,
		FirstBeaconWait:       30 * time.Second,
	}
}

// ──────────────────────────────────────────────
//  Listener
// ──────────────────────────────────────────────

// Listener accepts TLS connections from agents and processes the
// Codé TLV protocol.
type Listener struct {
	cfg      Config
	sessions *session.Manager
	audit    *audit.Logger
	logger   *log.Logger

	ln     net.Listener
	wg     sync.WaitGroup
	stopCh chan struct{}
}

// New creates a new Listener.
func New(cfg Config, sessions *session.Manager, auditLog *audit.Logger) *Listener {
	return &Listener{
		cfg:      cfg,
		sessions: sessions,
		audit:    auditLog,
		logger:   log.New(os.Stdout, "[listener] ", log.LstdFlags|log.Lmsgprefix),
		stopCh:   make(chan struct{}),
	}
}

// Start begins accepting TLS connections. It blocks until Stop is called.
func (l *Listener) Start() error {
	tlsCfg, err := l.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("listener: TLS config: %w", err)
	}

	ln, err := tls.Listen("tcp", l.cfg.ListenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("listener: bind %s: %w", l.cfg.ListenAddr, err)
	}
	l.ln = ln

	l.logger.Printf("Listening on %s (TLS 1.3)", l.cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-l.stopCh:
				return nil // graceful shutdown
			default:
				l.logger.Printf("accept error: %v", err)
				continue
			}
		}

		l.wg.Add(1)
		go l.handleConn(conn)
	}
}

// Stop gracefully shuts down the listener and waits for all
// connection handlers to finish.
func (l *Listener) Stop() {
	close(l.stopCh)
	if l.ln != nil {
		l.ln.Close()
	}
	l.wg.Wait()
}

// ──────────────────────────────────────────────
//  TLS configuration
// ──────────────────────────────────────────────

func (l *Listener) buildTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(l.cfg.CertFile, l.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	// If a CA file is provided, set up the CA pool (used for reference/logging).
	if l.cfg.CAFile != "" {
		caPEM, err := os.ReadFile(l.cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		cfg.RootCAs = pool
	}

	return cfg, nil
}

// ──────────────────────────────────────────────
//  Connection handler
// ──────────────────────────────────────────────

func (l *Listener) handleConn(conn net.Conn) {
	defer l.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	l.logger.Printf("New connection from %s", remoteAddr)

	// Create a session in INIT state.
	sess := session.NewSession(remoteAddr, l.cfg.DefaultBeaconInterval, l.cfg.DefaultJitter)
	l.sessions.Add(sess)

	// Phase 1: Wait for REGISTER
	conn.SetReadDeadline(time.Now().Add(l.cfg.RegisterTimeout))

	msg, err := codec.ReadMessage(conn)
	if err != nil {
		l.logger.Printf("[%s] register read error: %v", remoteAddr, err)
		l.sessions.Remove(sess.ID)
		return
	}

	if msg.Type != codec.MsgRegister {
		l.logger.Printf("[%s] expected REGISTER, got %s", remoteAddr, msg.Type)
		l.sessions.Remove(sess.ID)
		return
	}

	// Extract registration fields.
	hostname := msg.GetFieldString(codec.FieldHostname)
	osType := msg.GetFieldString(codec.FieldOS)
	arch := msg.GetFieldString(codec.FieldArch)
	osVersion := msg.GetFieldString(codec.FieldOSVersion)
	username := msg.GetFieldString(codec.FieldUsername)

	if err := sess.Register(hostname, osType, arch, osVersion, username); err != nil {
		l.logger.Printf("[%s] register failed: %v", remoteAddr, err)
		l.sessions.Remove(sess.ID)
		return
	}

	// Validate sequence number from REGISTER (should be 1).
	regSeq := msg.GetFieldUint32(codec.FieldSeqNumber)
	if regSeq > 0 {
		sess.ValidateSeq(regSeq)
	}

	l.logger.Printf("[%s] REGISTERED session=%s host=%s os=%s/%s user=%s",
		remoteAddr, sess.ID, hostname, osType, arch, username)

	if l.audit != nil {
		l.audit.SessionEvent(audit.EventSessionRegister, sess.ID, remoteAddr,
			fmt.Sprintf("hostname=%s os=%s/%s user=%s", hostname, osType, arch, username))
	}

	// Send REGISTER response with session ID and server config.
	sessionIDBytes := uuidToBytes(sess.ID)
	resp := codec.NewMessage(codec.MsgRegister).
		AddBytes(codec.FieldSessionID, sessionIDBytes).
		AddUint64(codec.FieldTimestamp, uint64(time.Now().Unix())).
		AddUint32(codec.FieldBeaconInterval, l.cfg.DefaultBeaconInterval).
		AddByte(codec.FieldJitter, l.cfg.DefaultJitter)

	if err := codec.WriteMessage(conn, resp); err != nil {
		l.logger.Printf("[%s] register response write error: %v", remoteAddr, err)
		l.sessions.Remove(sess.ID)
		return
	}

	// Phase 2: Wait for first BEACON (transitions to ACTIVE).
	conn.SetReadDeadline(time.Now().Add(l.cfg.FirstBeaconWait))

	msg, err = codec.ReadMessage(conn)
	if err != nil {
		l.logger.Printf("[%s] first beacon read error: %v", remoteAddr, err)
		sess.Transition(session.StateShutdown)
		return
	}

	if msg.Type != codec.MsgBeacon {
		l.logger.Printf("[%s] expected BEACON, got %s", remoteAddr, msg.Type)
		sess.Transition(session.StateShutdown)
		return
	}

	if err := sess.Transition(session.StateActive); err != nil {
		l.logger.Printf("[%s] transition to ACTIVE failed: %v", remoteAddr, err)
		return
	}

	sess.Touch()

	if l.audit != nil {
		l.audit.SessionEvent(audit.EventSessionActive, sess.ID, remoteAddr, "first beacon received")
	}

	l.logger.Printf("[%s] session %s ACTIVE", remoteAddr, sess.ID)

	// Handle the first beacon's response (dispatch tasks or ack).
	l.handleBeacon(conn, sess)

	// Phase 3: Main message loop.
	l.messageLoop(conn, sess)
}

// ──────────────────────────────────────────────
//  Main message loop
// ──────────────────────────────────────────────

func (l *Listener) messageLoop(conn net.Conn, sess *session.Session) {
	for {
		// Set read deadline based on beacon interval × 3.
		deadline := time.Duration(sess.BeaconInterval) * 3 * time.Second
		conn.SetReadDeadline(time.Now().Add(deadline))

		// Check for shutdown signal.
		select {
		case <-sess.ShutdownCh:
			l.sendShutdown(conn, sess, "operator requested shutdown")
			return
		case <-l.stopCh:
			l.sendShutdown(conn, sess, "server shutting down")
			return
		default:
		}

		msg, err := codec.ReadMessage(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || isTimeout(err) {
				l.logger.Printf("[%s] session %s: connection lost (%v)",
					sess.RemoteAddr, sess.ID, err)
				if l.audit != nil {
					if isTimeout(err) {
						l.audit.SessionEvent(audit.EventSessionTimeout, sess.ID,
							sess.RemoteAddr, "beacon deadline exceeded")
					} else {
						l.audit.SessionEvent(audit.EventSessionDisconnect, sess.ID,
							sess.RemoteAddr, err.Error())
					}
				}
			} else {
				l.logger.Printf("[%s] session %s: read error: %v",
					sess.RemoteAddr, sess.ID, err)
			}
			sess.Transition(session.StateShutdown)
			return
		}

		// Validate sequence number.
		if seq := msg.GetFieldUint32(codec.FieldSeqNumber); seq > 0 {
			if !sess.ValidateSeq(seq) {
				l.logger.Printf("[%s] session %s: sequence violation (got %d)",
					sess.RemoteAddr, sess.ID, seq)
				sess.Transition(session.StateShutdown)
				return
			}
		}

		sess.Touch()

		switch msg.Type {
		case codec.MsgBeacon:
			l.handleBeacon(conn, sess)

		case codec.MsgResult:
			l.handleResult(conn, sess, msg)

		case codec.MsgShutdown:
			// Agent-initiated shutdown acknowledgement.
			l.logger.Printf("[%s] session %s: agent acknowledged shutdown",
				sess.RemoteAddr, sess.ID)
			sess.Transition(session.StateShutdown)
			if l.audit != nil {
				l.audit.SessionEvent(audit.EventSessionShutdown, sess.ID,
					sess.RemoteAddr, "agent acknowledged")
			}
			return

		default:
			l.logger.Printf("[%s] session %s: unexpected message type %s",
				sess.RemoteAddr, sess.ID, msg.Type)
			sess.Transition(session.StateShutdown)
			return
		}
	}
}

// ──────────────────────────────────────────────
//  Message handlers
// ──────────────────────────────────────────────

// handleBeacon processes a BEACON and sends back queued tasks or an
// empty beacon acknowledgement.
func (l *Listener) handleBeacon(conn net.Conn, sess *session.Session) {
	// Check if shutdown was requested while we were processing.
	select {
	case <-sess.ShutdownCh:
		l.sendShutdown(conn, sess, "operator requested shutdown")
		return
	default:
	}

	// Dequeue all pending tasks.
	tasks := sess.TaskQueue.DequeueAll()

	if len(tasks) == 0 {
		// Send empty BEACON ack (header only, no TLV fields).
		ack := codec.NewMessage(codec.MsgBeacon)
		if err := codec.WriteMessage(conn, ack); err != nil {
			l.logger.Printf("[%s] session %s: beacon ack write error: %v",
				sess.RemoteAddr, sess.ID, err)
		}
		return
	}

	// Send each task as a TASK message.
	for _, task := range tasks {
		taskIDBytes := uuidToBytes(task.ID)
		taskMsg := codec.NewMessage(codec.MsgTask).
			AddBytes(codec.FieldTaskID, taskIDBytes).
			AddUint16(codec.FieldTaskType, uint16(task.Type)).
			AddBytes(codec.FieldTaskData, task.Data)

		if err := codec.WriteMessage(conn, taskMsg); err != nil {
			l.logger.Printf("[%s] session %s: task write error: %v",
				sess.RemoteAddr, sess.ID, err)
			return
		}

		l.logger.Printf("[%s] session %s: dispatched task %s (type=%s)",
			sess.RemoteAddr, sess.ID, task.ID, task.Type)

		if l.audit != nil {
			l.audit.TaskEvent(audit.EventTaskDispatched, sess.ID, task.Operator,
				task.Type.String(), task.ID, string(task.Data))
		}
	}
}

// handleResult processes a RESULT message from the agent.
func (l *Listener) handleResult(conn net.Conn, sess *session.Session, msg *codec.Message) {
	taskIDField := msg.GetField(codec.FieldResultTaskID)
	var taskID string
	if taskIDField != nil && len(taskIDField.Value) == 16 {
		taskID = bytesToUUID(taskIDField.Value)
	}

	status := msg.GetFieldByte(codec.FieldResultStatus)
	resultData := msg.GetField(codec.FieldResultData)
	resultError := msg.GetFieldString(codec.FieldResultError)
	elapsed := msg.GetFieldUint32(codec.FieldResultElapsed)

	var data []byte
	if resultData != nil {
		data = resultData.Value
	}

	result := session.Result{
		TaskID:     taskID,
		Status:     status,
		Data:       data,
		Error:      resultError,
		ElapsedMs:  elapsed,
		ReceivedAt: time.Now(),
	}

	sess.AddResult(result)

	statusStr := "success"
	switch status {
	case 1:
		statusStr = "error"
	case 2:
		statusStr = "timeout"
	}

	l.logger.Printf("[%s] session %s: result for task %s (status=%s, %d bytes, %dms)",
		sess.RemoteAddr, sess.ID, taskID, statusStr, len(data), elapsed)

	if l.audit != nil {
		l.audit.TaskEvent(audit.EventTaskResult, sess.ID, "", "",
			taskID, fmt.Sprintf("status=%s elapsed=%dms data_len=%d", statusStr, elapsed, len(data)))
	}
}

// sendShutdown sends a SHUTDOWN message to the agent.
func (l *Listener) sendShutdown(conn net.Conn, sess *session.Session, reason string) {
	shutMsg := codec.NewMessage(codec.MsgShutdown).
		AddString(codec.FieldShutdownReason, reason)

	if err := codec.WriteMessage(conn, shutMsg); err != nil {
		l.logger.Printf("[%s] session %s: shutdown write error: %v",
			sess.RemoteAddr, sess.ID, err)
	} else {
		l.logger.Printf("[%s] session %s: sent SHUTDOWN (%s)",
			sess.RemoteAddr, sess.ID, reason)
	}

	sess.Transition(session.StateShutdown)

	if l.audit != nil {
		l.audit.SessionEvent(audit.EventSessionShutdown, sess.ID,
			sess.RemoteAddr, reason)
	}
}

// ──────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────

// uuidToBytes converts a UUID hex string to 16 raw bytes.
func uuidToBytes(id string) []byte {
	parsed, err := uuid.Parse(id)
	if err != nil {
		// Fallback: try hex-decoding without dashes.
		b, _ := hex.DecodeString(id)
		if len(b) == 16 {
			return b
		}
		return make([]byte, 16)
	}
	return parsed[:]
}

// bytesToUUID converts 16 raw bytes to a UUID hex string.
func bytesToUUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	u, err := uuid.FromBytes(b)
	if err != nil {
		return hex.EncodeToString(b)
	}
	return u.String()
}

// isTimeout returns true if the error is a network timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
