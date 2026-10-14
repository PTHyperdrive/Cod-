// Package client implements the gRPC client for the C2 Team Server.
//
// It wraps all gRPC service calls with a typed client that handles
// connection setup (mutual TLS) and provides a clean interface for
// the console's command handlers.
//
// ACADEMIC/EDUCATIONAL USE ONLY.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ──────────────────────────────────────────────
//  Proto types (mirrored from server/proto)
// ──────────────────────────────────────────────
//
// We duplicate the minimal proto types here so that the console
// module doesn't need to import from the server module directly.
// In a production setup, both would import from a shared proto
// package published as its own module.

// SessionState represents the lifecycle state of an agent session.
type SessionState int32

const (
	SessionStateUnspecified SessionState = 0
	SessionStateRegistered  SessionState = 1
	SessionStateActive      SessionState = 2
	SessionStateShutdown    SessionState = 3
)

// String returns a human-readable name for the session state.
func (s SessionState) String() string {
	switch s {
	case SessionStateRegistered:
		return "REGISTERED"
	case SessionStateActive:
		return "ACTIVE"
	case SessionStateShutdown:
		return "SHUTDOWN"
	default:
		return "UNKNOWN"
	}
}

// TaskType enumerates the tasks that can be dispatched to an agent.
type TaskType int32

const (
	TaskTypeUnspecified TaskType = 0
	TaskTypeExec       TaskType = 1
	TaskTypeUpload     TaskType = 2
	TaskTypeDownload   TaskType = 3
	TaskTypeSysinfo    TaskType = 4
	TaskTypeSleep      TaskType = 5
	TaskTypeExit       TaskType = 6
	TaskTypeSelfPreserve TaskType = 7 // Toggle self-preservation
)

// SessionInfo carries detailed information about an agent session.
type SessionInfo struct {
	SessionID      string       `json:"session_id"`
	Hostname       string       `json:"hostname"`
	OS             string       `json:"os"`
	Arch           string       `json:"arch"`
	State          SessionState `json:"state"`
	RegisteredAt   int64        `json:"registered_at"`
	LastSeen       int64        `json:"last_seen"`
	BeaconInterval uint32       `json:"beacon_interval"`
	Jitter         uint32       `json:"jitter"`
	SeqNumber      uint32       `json:"seq_number"`
	RemoteAddr     string       `json:"remote_addr"`
}

// TaskResult carries the result of a completed task.
type TaskResult struct {
	TaskID     string `json:"task_id"`
	SessionID  string `json:"session_id"`
	ResultData []byte `json:"result_data"`
	ErrorMsg   string `json:"error_msg"`
	ReceivedAt int64  `json:"received_at"`
}

// ──────────────────────────────────────────────
//  Client
// ──────────────────────────────────────────────

// Config holds the configuration for a Client connection.
type Config struct {
	ServerAddr string // e.g. "10.13.37.1:50051"
	CertFile   string // Operator client certificate PEM
	KeyFile    string // Operator client private key PEM
	CAFile     string // CA certificate PEM (to verify the server)
}

// Client wraps a gRPC connection to the Team Server.
type Client struct {
	cfg  Config
	conn *grpc.ClientConn
}

// New creates a new Client (does not connect yet).
func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

// Connect establishes the mTLS gRPC connection to the Team Server.
func (c *Client) Connect() error {
	creds, err := c.buildCredentials()
	if err != nil {
		return fmt.Errorf("client: credentials: %w", err)
	}

	conn, err := grpc.Dial(c.cfg.ServerAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("client: dial %s: %w", c.cfg.ServerAddr, err)
	}

	c.conn = conn
	return nil
}

// Close shuts down the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// buildCredentials constructs TLS transport credentials with mutual auth.
func (c *Client) buildCredentials() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(c.cfg.CertFile, c.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	caPEM, err := os.ReadFile(c.cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(tlsCfg), nil
}

// ──────────────────────────────────────────────
//  RPC calls
// ──────────────────────────────────────────────

// defaultCtx creates a context with a 10-second timeout for RPCs.
func defaultCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// ListSessions retrieves all tracked sessions from the server.
func (c *Client) ListSessions() ([]*SessionInfo, error) {
	ctx, cancel := defaultCtx()
	defer cancel()

	// Use the raw gRPC connection to invoke the RPC.
	out := new(listSessionsResponse)
	err := c.conn.Invoke(ctx, "/c2.C2Service/ListSessions", &listSessionsRequest{}, out)
	if err != nil {
		return nil, fmt.Errorf("ListSessions: %w", err)
	}

	return out.Sessions, nil
}

// GetSession retrieves detailed information about a single session.
func (c *Client) GetSession(sessionID string) (*SessionInfo, error) {
	ctx, cancel := defaultCtx()
	defer cancel()

	in := &getSessionRequest{SessionID: sessionID}
	out := new(SessionInfo)
	err := c.conn.Invoke(ctx, "/c2.C2Service/GetSession", in, out)
	if err != nil {
		return nil, fmt.Errorf("GetSession: %w", err)
	}

	return out, nil
}

// QueueTask enqueues a task for delivery to an agent.
func (c *Client) QueueTask(sessionID string, taskType TaskType, data []byte, operator string) (string, error) {
	ctx, cancel := defaultCtx()
	defer cancel()

	in := &queueTaskRequest{
		SessionID: sessionID,
		TaskType:  int32(taskType),
		TaskData:  data,
		Operator:  operator,
	}
	out := new(queueTaskResponse)
	err := c.conn.Invoke(ctx, "/c2.C2Service/QueueTask", in, out)
	if err != nil {
		return "", fmt.Errorf("QueueTask: %w", err)
	}

	return out.TaskID, nil
}

// GetResults retrieves collected results for a given session.
func (c *Client) GetResults(sessionID string) ([]*TaskResult, error) {
	ctx, cancel := defaultCtx()
	defer cancel()

	in := &getResultsRequest{SessionID: sessionID}
	out := new(getResultsResponse)
	err := c.conn.Invoke(ctx, "/c2.C2Service/GetResults", in, out)
	if err != nil {
		return nil, fmt.Errorf("GetResults: %w", err)
	}

	return out.Results, nil
}

// Shutdown requests graceful shutdown of a specific agent session.
func (c *Client) Shutdown(sessionID, operator string) error {
	ctx, cancel := defaultCtx()
	defer cancel()

	in := &shutdownRequest{SessionID: sessionID, Operator: operator}
	out := new(shutdownResponse)
	err := c.conn.Invoke(ctx, "/c2.C2Service/Shutdown", in, out)
	if err != nil {
		return fmt.Errorf("Shutdown: %w", err)
	}

	return nil
}

// BroadcastShutdown requests shutdown of ALL active agent sessions.
func (c *Client) BroadcastShutdown(operator string) (uint32, error) {
	ctx, cancel := defaultCtx()
	defer cancel()

	in := &broadcastShutdownRequest{Operator: operator}
	out := new(broadcastShutdownResponse)
	err := c.conn.Invoke(ctx, "/c2.C2Service/BroadcastShutdown", in, out)
	if err != nil {
		return 0, fmt.Errorf("BroadcastShutdown: %w", err)
	}

	return out.SessionsNotified, nil
}

// ──────────────────────────────────────────────
//  Internal proto-compatible message types
// ──────────────────────────────────────────────
//
// These minimal struct types are registered with protobuf encoding
// so that gRPC can serialize/deserialize them on the wire. They
// mirror the server's proto definitions.

type listSessionsRequest struct{}
type listSessionsResponse struct {
	Sessions []*SessionInfo `protobuf:"bytes,1,rep,name=sessions,proto3" json:"sessions,omitempty"`
}

type getSessionRequest struct {
	SessionID string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
}

type queueTaskRequest struct {
	SessionID string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	TaskType  int32  `protobuf:"varint,2,opt,name=task_type,json=taskType,proto3" json:"task_type,omitempty"`
	TaskData  []byte `protobuf:"bytes,3,opt,name=task_data,json=taskData,proto3" json:"task_data,omitempty"`
	Operator  string `protobuf:"bytes,4,opt,name=operator,proto3" json:"operator,omitempty"`
}

type queueTaskResponse struct {
	TaskID string `protobuf:"bytes,1,opt,name=task_id,json=taskId,proto3" json:"task_id,omitempty"`
	Queued bool   `protobuf:"varint,2,opt,name=queued,proto3" json:"queued,omitempty"`
}

type getResultsRequest struct {
	SessionID string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
}

type getResultsResponse struct {
	Results []*TaskResult `protobuf:"bytes,1,rep,name=results,proto3" json:"results,omitempty"`
}

type shutdownRequest struct {
	SessionID string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	Operator  string `protobuf:"bytes,2,opt,name=operator,proto3" json:"operator,omitempty"`
}

type shutdownResponse struct {
	Success bool `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
}

type broadcastShutdownRequest struct {
	Operator string `protobuf:"bytes,1,opt,name=operator,proto3" json:"operator,omitempty"`
}

type broadcastShutdownResponse struct {
	SessionsNotified uint32 `protobuf:"varint,1,opt,name=sessions_notified,json=sessionsNotified,proto3" json:"sessions_notified,omitempty"`
}

// ──────────────────────────────────────────────
//  Proto registration stubs
// ──────────────────────────────────────────────
//
// For gRPC's proto codec to work, each message type must implement
// the proto.Message interface (ProtoReflect, ProtoMessage, Reset).
// Since we're not using protoc-generated code, we provide minimal
// stubs. These are compatible with the JSON/proto encoding that
// gRPC uses for wire serialization.

func (*listSessionsRequest) ProtoMessage()  {}
func (*listSessionsRequest) Reset()         {}
func (*listSessionsRequest) String() string { return "ListSessionsRequest" }

func (*listSessionsResponse) ProtoMessage()  {}
func (*listSessionsResponse) Reset()         {}
func (*listSessionsResponse) String() string { return "ListSessionsResponse" }

func (*getSessionRequest) ProtoMessage()  {}
func (*getSessionRequest) Reset()         {}
func (*getSessionRequest) String() string { return "GetSessionRequest" }

func (*SessionInfo) ProtoMessage()  {}
func (*SessionInfo) Reset()         {}
func (s *SessionInfo) String() string {
	return fmt.Sprintf("SessionInfo{id=%s host=%s state=%s}", s.SessionID, s.Hostname, s.State)
}

func (*queueTaskRequest) ProtoMessage()  {}
func (*queueTaskRequest) Reset()         {}
func (*queueTaskRequest) String() string { return "QueueTaskRequest" }

func (*queueTaskResponse) ProtoMessage()  {}
func (*queueTaskResponse) Reset()         {}
func (*queueTaskResponse) String() string { return "QueueTaskResponse" }

func (*getResultsRequest) ProtoMessage()  {}
func (*getResultsRequest) Reset()         {}
func (*getResultsRequest) String() string { return "GetResultsRequest" }

func (*getResultsResponse) ProtoMessage()  {}
func (*getResultsResponse) Reset()         {}
func (*getResultsResponse) String() string { return "GetResultsResponse" }

func (*TaskResult) ProtoMessage()  {}
func (*TaskResult) Reset()         {}
func (*TaskResult) String() string { return "TaskResult" }

func (*shutdownRequest) ProtoMessage()  {}
func (*shutdownRequest) Reset()         {}
func (*shutdownRequest) String() string { return "ShutdownRequest" }

func (*shutdownResponse) ProtoMessage()  {}
func (*shutdownResponse) Reset()         {}
func (*shutdownResponse) String() string { return "ShutdownResponse" }

func (*broadcastShutdownRequest) ProtoMessage()  {}
func (*broadcastShutdownRequest) Reset()         {}
func (*broadcastShutdownRequest) String() string { return "BroadcastShutdownRequest" }

func (*broadcastShutdownResponse) ProtoMessage()  {}
func (*broadcastShutdownResponse) Reset()         {}
func (*broadcastShutdownResponse) String() string { return "BroadcastShutdownResponse" }
