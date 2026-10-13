// Package codec implements the Codé TLV (Type-Length-Value) wire codec.
//
// Wire format (per message on the wire):
//
//	┌──────────────────────────────────┬──────────────────────────────────┐
//	│  Length prefix (4 bytes, BE)     │  TLV body (variable)            │
//	└──────────────────────────────────┴──────────────────────────────────┘
//
// The body begins with a 1-byte message type, followed by zero or more
// TLV fields.  Each TLV field is:
//
//	┌──────────┬──────────────┬─────────────────────┐
//	│ Type 2B  │ Length 4B    │ Value (L bytes)      │
//	└──────────┴──────────────┴─────────────────────┘
//
// All multi-byte integers are big-endian (network byte order).
//
// ACADEMIC/EDUCATIONAL USE ONLY.
package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

// MaxFrameSize is the maximum allowed message body size (1 MiB).
const MaxFrameSize = 1 << 20 // 1,048,576 bytes

// TLV header sizes.
const (
	tlvTypeSize   = 2 // bytes for the field type
	tlvLengthSize = 4 // bytes for the field length
	tlvHeaderSize = tlvTypeSize + tlvLengthSize // 6 bytes total
)

// ──────────────────────────────────────────────
//  Errors
// ──────────────────────────────────────────────

var (
	// ErrFrameTooLarge is returned when a frame exceeds MaxFrameSize.
	ErrFrameTooLarge = errors.New("codec: frame exceeds maximum size")

	// ErrEmptyFrame is returned when a frame has zero body length.
	ErrEmptyFrame = errors.New("codec: empty frame body")

	// ErrTruncatedTLV is returned when a TLV field header or value is incomplete.
	ErrTruncatedTLV = errors.New("codec: truncated TLV field")

	// ErrTLVOverflow is returned when a TLV field length exceeds remaining body data.
	ErrTLVOverflow = errors.New("codec: TLV field value overflows body")
)

// ──────────────────────────────────────────────
//  Message types
// ──────────────────────────────────────────────

// MessageType identifies the kind of protocol message.
type MessageType byte

const (
	MsgRegister MessageType = 0x01 // Agent → Server: registration handshake
	MsgBeacon   MessageType = 0x02 // Agent → Server: periodic heartbeat
	MsgTask     MessageType = 0x03 // Server → Agent: task assignment
	MsgResult   MessageType = 0x04 // Agent → Server: task result
	MsgShutdown MessageType = 0x05 // Server → Agent: graceful shutdown
)

// String returns a human-readable name for the message type.
func (mt MessageType) String() string {
	switch mt {
	case MsgRegister:
		return "REGISTER"
	case MsgBeacon:
		return "BEACON"
	case MsgTask:
		return "TASK"
	case MsgResult:
		return "RESULT"
	case MsgShutdown:
		return "SHUTDOWN"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(mt))
	}
}

// Valid returns true if the message type is a known protocol message.
func (mt MessageType) Valid() bool {
	switch mt {
	case MsgRegister, MsgBeacon, MsgTask, MsgResult, MsgShutdown:
		return true
	default:
		return false
	}
}

// ──────────────────────────────────────────────
//  Field types
// ──────────────────────────────────────────────

// FieldType identifies a TLV field within a message body.
type FieldType uint16

const (
	// Common fields (0x0001–0x000F)
	FieldHostname     FieldType = 0x0001 // UTF-8 string: machine hostname
	FieldOS           FieldType = 0x0002 // UTF-8 string: operating system
	FieldArch         FieldType = 0x0003 // UTF-8 string: CPU architecture
	FieldOSVersion    FieldType = 0x0004 // UTF-8 string: OS version string
	FieldAgentVersion FieldType = 0x0005 // UTF-8 string: agent build version
	FieldAgentPID     FieldType = 0x0006 // uint32: agent process ID
	FieldUsername     FieldType = 0x0007 // UTF-8 string: current username

	// Registration response (0x0010–0x001F)
	FieldSessionID      FieldType = 0x0010 // 16 bytes: UUID v4 (raw)
	FieldTimestamp       FieldType = 0x0011 // uint64: Unix epoch seconds
	FieldBeaconInterval FieldType = 0x0012 // uint32: beacon interval (seconds)
	FieldJitter         FieldType = 0x0013 // uint8: jitter percentage (0–100)

	// Beacon fields (0x0020–0x002F)
	FieldAgentUptime FieldType = 0x0020 // uint64: seconds since agent start
	FieldTaskSlots   FieldType = 0x0021 // uint8: available task slots

	// Task fields (0x0030–0x003F)
	FieldTaskID      FieldType = 0x0030 // 16 bytes: UUID v4 (raw)
	FieldTaskType    FieldType = 0x0031 // uint16: task type code
	FieldTaskData    FieldType = 0x0032 // bytes: task-specific arguments
	FieldTaskTimeout FieldType = 0x0033 // uint32: max execution time (seconds)

	// Result fields (0x0040–0x004F)
	FieldResultTaskID  FieldType = 0x0040 // 16 bytes: task ID this result is for
	FieldResultStatus  FieldType = 0x0041 // uint8: 0=success, 1=error, 2=timeout
	FieldResultData    FieldType = 0x0042 // bytes: task output data
	FieldResultError   FieldType = 0x0043 // UTF-8 string: error message
	FieldResultElapsed FieldType = 0x0044 // uint32: execution time (milliseconds)

	// Shutdown fields (0x0050–0x005F)
	FieldShutdownReason FieldType = 0x0050 // UTF-8 string: reason for shutdown

	// Internal / codec-level fields
	FieldSeqNumber FieldType = 0x0060 // uint32: sequence number (codec-level)
)

// String returns a human-readable name for the field type.
func (ft FieldType) String() string {
	switch ft {
	case FieldHostname:
		return "Hostname"
	case FieldOS:
		return "OS"
	case FieldArch:
		return "Arch"
	case FieldOSVersion:
		return "OSVersion"
	case FieldAgentVersion:
		return "AgentVersion"
	case FieldAgentPID:
		return "AgentPID"
	case FieldUsername:
		return "Username"
	case FieldSessionID:
		return "SessionID"
	case FieldTimestamp:
		return "Timestamp"
	case FieldBeaconInterval:
		return "BeaconInterval"
	case FieldJitter:
		return "Jitter"
	case FieldAgentUptime:
		return "AgentUptime"
	case FieldTaskSlots:
		return "TaskSlots"
	case FieldTaskID:
		return "TaskID"
	case FieldTaskType:
		return "TaskType"
	case FieldTaskData:
		return "TaskData"
	case FieldTaskTimeout:
		return "TaskTimeout"
	case FieldResultTaskID:
		return "ResultTaskID"
	case FieldResultStatus:
		return "ResultStatus"
	case FieldResultData:
		return "ResultData"
	case FieldResultError:
		return "ResultError"
	case FieldResultElapsed:
		return "ResultElapsed"
	case FieldShutdownReason:
		return "ShutdownReason"
	case FieldSeqNumber:
		return "SeqNumber"
	default:
		return fmt.Sprintf("UNKNOWN(0x%04x)", uint16(ft))
	}
}

// ──────────────────────────────────────────────
//  Field
// ──────────────────────────────────────────────

// Field represents a single decoded TLV field.
type Field struct {
	Type  FieldType // Field type identifier
	Value []byte    // Raw value bytes
}

// ──────────────────────────────────────────────
//  Message
// ──────────────────────────────────────────────

// Message represents a decoded protocol message consisting of a type
// and zero or more TLV fields.
type Message struct {
	Type   MessageType // Message type (REGISTER, BEACON, etc.)
	Fields []Field     // TLV fields in order of appearance
}

// ──────────────────────────────────────────────
//  Message construction (builder pattern)
// ──────────────────────────────────────────────

// NewMessage creates a new Message with the given type and no fields.
func NewMessage(mt MessageType) *Message {
	return &Message{Type: mt}
}

// AddBytes appends a raw byte-slice field and returns the message for chaining.
func (m *Message) AddBytes(ft FieldType, value []byte) *Message {
	// Copy value to avoid aliasing the caller's slice.
	v := make([]byte, len(value))
	copy(v, value)
	m.Fields = append(m.Fields, Field{Type: ft, Value: v})
	return m
}

// AddString appends a UTF-8 string field and returns the message for chaining.
func (m *Message) AddString(ft FieldType, value string) *Message {
	m.Fields = append(m.Fields, Field{Type: ft, Value: []byte(value)})
	return m
}

// AddUint16 appends a 2-byte big-endian uint16 field.
func (m *Message) AddUint16(ft FieldType, value uint16) *Message {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, value)
	m.Fields = append(m.Fields, Field{Type: ft, Value: buf})
	return m
}

// AddUint32 appends a 4-byte big-endian uint32 field.
func (m *Message) AddUint32(ft FieldType, value uint32) *Message {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	m.Fields = append(m.Fields, Field{Type: ft, Value: buf})
	return m
}

// AddUint64 appends an 8-byte big-endian uint64 field.
func (m *Message) AddUint64(ft FieldType, value uint64) *Message {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	m.Fields = append(m.Fields, Field{Type: ft, Value: buf})
	return m
}

// AddByte appends a single-byte field.
func (m *Message) AddByte(ft FieldType, value byte) *Message {
	m.Fields = append(m.Fields, Field{Type: ft, Value: []byte{value}})
	return m
}

// ──────────────────────────────────────────────
//  Field accessors
// ──────────────────────────────────────────────

// GetField returns the first field matching the given type, or nil if
// not found.
func (m *Message) GetField(ft FieldType) *Field {
	for i := range m.Fields {
		if m.Fields[i].Type == ft {
			return &m.Fields[i]
		}
	}
	return nil
}

// GetFieldString returns the value of the first matching field as a
// UTF-8 string, or "" if the field is not present.
func (m *Message) GetFieldString(ft FieldType) string {
	f := m.GetField(ft)
	if f == nil {
		return ""
	}
	return string(f.Value)
}

// GetFieldUint16 returns the value of the first matching field as a
// big-endian uint16. Returns 0 if the field is missing or not exactly
// 2 bytes.
func (m *Message) GetFieldUint16(ft FieldType) uint16 {
	f := m.GetField(ft)
	if f == nil || len(f.Value) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(f.Value)
}

// GetFieldUint32 returns the value of the first matching field as a
// big-endian uint32. Returns 0 if the field is missing or not exactly
// 4 bytes.
func (m *Message) GetFieldUint32(ft FieldType) uint32 {
	f := m.GetField(ft)
	if f == nil || len(f.Value) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(f.Value)
}

// GetFieldUint64 returns the value of the first matching field as a
// big-endian uint64. Returns 0 if the field is missing or not exactly
// 8 bytes.
func (m *Message) GetFieldUint64(ft FieldType) uint64 {
	f := m.GetField(ft)
	if f == nil || len(f.Value) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(f.Value)
}

// GetFieldByte returns the value of the first matching field as a
// single byte. Returns 0 if the field is missing or not exactly 1 byte.
func (m *Message) GetFieldByte(ft FieldType) byte {
	f := m.GetField(ft)
	if f == nil || len(f.Value) != 1 {
		return 0
	}
	return f.Value[0]
}

// ──────────────────────────────────────────────
//  Encoding
// ──────────────────────────────────────────────

// Encode serializes a Message into a length-prefixed wire frame.
//
// Wire layout:
//
//	[4B length prefix (BE)] [1B msg type] [TLV field 1] [TLV field 2] ...
//
// Returns the complete frame bytes or an error if the body exceeds
// MaxFrameSize.
func Encode(msg *Message) ([]byte, error) {
	// Calculate body size: 1 byte for message type + all TLV fields.
	bodySize := 1 // message type byte
	for _, f := range msg.Fields {
		bodySize += tlvHeaderSize + len(f.Value)
	}

	if bodySize > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}

	// Allocate the full frame: 4-byte prefix + body.
	frame := make([]byte, 4+bodySize)

	// Write the length prefix.
	binary.BigEndian.PutUint32(frame[0:4], uint32(bodySize))

	// Write the message type.
	frame[4] = byte(msg.Type)

	// Write each TLV field.
	offset := 5
	for _, f := range msg.Fields {
		binary.BigEndian.PutUint16(frame[offset:offset+2], uint16(f.Type))
		binary.BigEndian.PutUint32(frame[offset+2:offset+6], uint32(len(f.Value)))
		copy(frame[offset+6:], f.Value)
		offset += tlvHeaderSize + len(f.Value)
	}

	return frame, nil
}

// ──────────────────────────────────────────────
//  Decoding
// ──────────────────────────────────────────────

// ReadMessage reads a single length-prefixed message from r and decodes it.
func ReadMessage(r io.Reader) (*Message, error) {
	// Read the 4-byte length prefix.
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("codec: read length prefix: %w", err)
	}

	bodyLen := binary.BigEndian.Uint32(prefix[:])

	// Validate length.
	if bodyLen == 0 {
		return nil, ErrEmptyFrame
	}
	if bodyLen > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}

	// Read the complete body.
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("codec: read body (%d bytes): %w", bodyLen, err)
	}

	return DecodeBody(body)
}

// DecodeBody decodes a message body (without the length prefix) into a
// Message. The body must begin with a 1-byte message type followed by
// zero or more TLV fields.
func DecodeBody(body []byte) (*Message, error) {
	if len(body) < 1 {
		return nil, ErrEmptyFrame
	}

	mt := MessageType(body[0])
	if !mt.Valid() {
		return nil, fmt.Errorf("codec: unknown message type 0x%02x", byte(mt))
	}

	msg := &Message{Type: mt}

	// Parse TLV fields from the remaining body.
	data := body[1:]
	for len(data) > 0 {
		if len(data) < tlvHeaderSize {
			return nil, ErrTruncatedTLV
		}

		fieldType := FieldType(binary.BigEndian.Uint16(data[0:2]))
		fieldLen := binary.BigEndian.Uint32(data[2:6])

		if int(fieldLen) > len(data)-tlvHeaderSize {
			return nil, ErrTLVOverflow
		}

		value := make([]byte, fieldLen)
		copy(value, data[tlvHeaderSize:tlvHeaderSize+int(fieldLen)])

		msg.Fields = append(msg.Fields, Field{
			Type:  fieldType,
			Value: value,
		})

		data = data[tlvHeaderSize+int(fieldLen):]
	}

	return msg, nil
}

// WriteMessage encodes the message and writes the complete frame to w.
func WriteMessage(w io.Writer, msg *Message) error {
	frame, err := Encode(msg)
	if err != nil {
		return err
	}

	_, err = w.Write(frame)
	if err != nil {
		return fmt.Errorf("codec: write frame: %w", err)
	}

	return nil
}
