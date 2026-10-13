package codec

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// ──────────────────────────────────────────────
//  Round-trip tests
// ──────────────────────────────────────────────

// TestRoundTripRegister verifies that a REGISTER message survives
// encode → decode without data loss.
func TestRoundTripRegister(t *testing.T) {
	sessionID := make([]byte, 16)
	for i := range sessionID {
		sessionID[i] = byte(i)
	}

	original := NewMessage(MsgRegister).
		AddBytes(FieldSessionID, sessionID).
		AddUint64(FieldTimestamp, 1700000000).
		AddUint32(FieldSeqNumber, 1).
		AddString(FieldHostname, "lab-victim-01").
		AddString(FieldOS, "linux").
		AddString(FieldArch, "amd64").
		AddUint32(FieldBeaconInterval, 30).
		AddByte(FieldJitter, 10)

	encoded, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadMessage(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if decoded.Type != MsgRegister {
		t.Errorf("message type: got %v, want REGISTER", decoded.Type)
	}
	if len(decoded.Fields) != len(original.Fields) {
		t.Fatalf("field count: got %d, want %d", len(decoded.Fields), len(original.Fields))
	}

	// Verify individual fields.
	if got := decoded.GetFieldString(FieldHostname); got != "lab-victim-01" {
		t.Errorf("hostname: got %q, want %q", got, "lab-victim-01")
	}
	if got := decoded.GetFieldUint32(FieldSeqNumber); got != 1 {
		t.Errorf("seq: got %d, want 1", got)
	}
	if got := decoded.GetFieldUint64(FieldTimestamp); got != 1700000000 {
		t.Errorf("timestamp: got %d, want 1700000000", got)
	}
	if got := decoded.GetFieldByte(FieldJitter); got != 10 {
		t.Errorf("jitter: got %d, want 10", got)
	}

	sid := decoded.GetField(FieldSessionID)
	if sid == nil || !bytes.Equal(sid.Value, sessionID) {
		t.Errorf("session ID mismatch")
	}
}

// TestRoundTripTask verifies a TASK message round-trip.
func TestRoundTripTask(t *testing.T) {
	original := NewMessage(MsgTask).
		AddUint16(FieldTaskType, 0x01). // EXEC
		AddString(FieldTaskData, "whoami")

	encoded, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadMessage(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if decoded.Type != MsgTask {
		t.Errorf("message type: got %v, want TASK", decoded.Type)
	}
	if got := decoded.GetFieldUint16(FieldTaskType); got != 0x01 {
		t.Errorf("task type: got 0x%04x, want 0x0001", got)
	}
	if got := decoded.GetFieldString(FieldTaskData); got != "whoami" {
		t.Errorf("task data: got %q, want %q", got, "whoami")
	}
}

// TestRoundTripResult verifies a RESULT message round-trip.
func TestRoundTripResult(t *testing.T) {
	resultData := []byte("root\n")
	original := NewMessage(MsgResult).
		AddBytes(FieldResultData, resultData)

	encoded, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadMessage(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if decoded.Type != MsgResult {
		t.Errorf("message type: got %v, want RESULT", decoded.Type)
	}
	rd := decoded.GetField(FieldResultData)
	if rd == nil || !bytes.Equal(rd.Value, resultData) {
		t.Errorf("result data mismatch")
	}
}

// TestRoundTripShutdown verifies a SHUTDOWN message with no fields.
func TestRoundTripShutdown(t *testing.T) {
	original := NewMessage(MsgShutdown)

	encoded, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadMessage(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if decoded.Type != MsgShutdown {
		t.Errorf("message type: got %v, want SHUTDOWN", decoded.Type)
	}
	if len(decoded.Fields) != 0 {
		t.Errorf("expected 0 fields, got %d", len(decoded.Fields))
	}
}

// TestRoundTripEmptyFields verifies fields with zero-length values.
func TestRoundTripEmptyFields(t *testing.T) {
	original := NewMessage(MsgBeacon).
		AddString(FieldHostname, "").
		AddBytes(FieldTaskData, []byte{})

	encoded, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := ReadMessage(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if decoded.Type != MsgBeacon {
		t.Errorf("message type: got %v, want BEACON", decoded.Type)
	}
	if got := decoded.GetFieldString(FieldHostname); got != "" {
		t.Errorf("hostname: got %q, want empty", got)
	}
}

// TestMultipleMessages verifies reading multiple concatenated frames.
func TestMultipleMessages(t *testing.T) {
	var buf bytes.Buffer

	msg1 := NewMessage(MsgBeacon).AddUint32(FieldSeqNumber, 42)
	msg2 := NewMessage(MsgResult).AddString(FieldResultData, "ok")

	enc1, _ := Encode(msg1)
	enc2, _ := Encode(msg2)
	buf.Write(enc1)
	buf.Write(enc2)

	r := bytes.NewReader(buf.Bytes())

	decoded1, err := ReadMessage(r)
	if err != nil {
		t.Fatalf("ReadMessage #1 failed: %v", err)
	}
	if decoded1.Type != MsgBeacon || decoded1.GetFieldUint32(FieldSeqNumber) != 42 {
		t.Errorf("message 1 mismatch")
	}

	decoded2, err := ReadMessage(r)
	if err != nil {
		t.Fatalf("ReadMessage #2 failed: %v", err)
	}
	if decoded2.Type != MsgResult || decoded2.GetFieldString(FieldResultData) != "ok" {
		t.Errorf("message 2 mismatch")
	}
}

// ──────────────────────────────────────────────
//  Malformed input tests
// ──────────────────────────────────────────────

// TestMalformedEmptyFrame tests decoding a frame with zero body length.
func TestMalformedEmptyFrame(t *testing.T) {
	// Frame prefix says 0 bytes of body.
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, 0)

	_, err := ReadMessage(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for zero-length frame body")
	}
}

// TestMalformedUnknownMessageType tests an invalid message type byte.
func TestMalformedUnknownMessageType(t *testing.T) {
	body := []byte{0xFF} // unknown type
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)

	_, err := ReadMessage(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for unknown message type")
	}
	if !strings.Contains(err.Error(), "unknown message type") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestMalformedTruncatedTLV tests a frame where a TLV field header is incomplete.
func TestMalformedTruncatedTLV(t *testing.T) {
	// Message type + 3 bytes (incomplete TLV header, need 6).
	body := []byte{byte(MsgRegister), 0x00, 0x01, 0x00}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)

	_, err := ReadMessage(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for truncated TLV header")
	}
}

// TestMalformedTLVOverflow tests a TLV field whose length exceeds the remaining data.
func TestMalformedTLVOverflow(t *testing.T) {
	// Message type + TLV header claiming 1000 bytes, but only 2 bytes of value present.
	body := make([]byte, 1+6+2) // msg_type + tlv_header + 2 value bytes
	body[0] = byte(MsgBeacon)
	binary.BigEndian.PutUint16(body[1:3], uint16(FieldHostname))
	binary.BigEndian.PutUint32(body[3:7], 1000) // claims 1000 bytes
	body[7] = 'A'
	body[8] = 'B'

	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)

	_, err := ReadMessage(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for TLV field overflow")
	}
}

// TestMalformedFrameTooLarge tests rejection of oversized frames.
func TestMalformedFrameTooLarge(t *testing.T) {
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, MaxFrameSize+1)

	_, err := ReadMessage(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for oversized frame")
	}
	if err != ErrFrameTooLarge {
		t.Errorf("expected ErrFrameTooLarge, got: %v", err)
	}
}

// TestMalformedTruncatedPrefix tests reading from a reader with insufficient data.
func TestMalformedTruncatedPrefix(t *testing.T) {
	_, err := ReadMessage(bytes.NewReader([]byte{0x00, 0x00}))
	if err == nil {
		t.Fatal("expected error for truncated prefix")
	}
}

// TestMalformedTruncatedBody tests a frame where the body is shorter than claimed.
func TestMalformedTruncatedBody(t *testing.T) {
	frame := make([]byte, 4+2) // prefix claims 100 bytes, only 2 present
	binary.BigEndian.PutUint32(frame, 100)
	frame[4] = byte(MsgRegister)
	frame[5] = 0x00

	_, err := ReadMessage(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected error for truncated body")
	}
}

// TestDecodeBodyDirect tests the DecodeBody function directly.
func TestDecodeBodyDirect(t *testing.T) {
	// Valid body: BEACON + one SeqNumber field.
	body := make([]byte, 1+6+4) // msg_type + tlv_hdr + 4-byte value
	body[0] = byte(MsgBeacon)
	binary.BigEndian.PutUint16(body[1:3], uint16(FieldSeqNumber))
	binary.BigEndian.PutUint32(body[3:7], 4)
	binary.BigEndian.PutUint32(body[7:11], 99)

	msg, err := DecodeBody(body)
	if err != nil {
		t.Fatalf("DecodeBody failed: %v", err)
	}
	if msg.Type != MsgBeacon {
		t.Errorf("type: got %v, want BEACON", msg.Type)
	}
	if got := msg.GetFieldUint32(FieldSeqNumber); got != 99 {
		t.Errorf("seq: got %d, want 99", got)
	}
}

// TestEncodeDecodeViaWriter verifies WriteMessage + ReadMessage via a pipe.
func TestEncodeDecodeViaWriter(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()

	msg := NewMessage(MsgTask).
		AddUint16(FieldTaskType, 0x04). // SYSINFO
		AddString(FieldTaskData, "")

	go func() {
		defer pw.Close()
		if err := WriteMessage(pw, msg); err != nil {
			t.Errorf("WriteMessage failed: %v", err)
		}
	}()

	decoded, err := ReadMessage(pr)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	if decoded.Type != MsgTask {
		t.Errorf("type: got %v, want TASK", decoded.Type)
	}
	if got := decoded.GetFieldUint16(FieldTaskType); got != 0x04 {
		t.Errorf("task type: got 0x%04x, want 0x0004", got)
	}
}

// TestMessageTypeString tests String() and Valid() for coverage.
func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		mt    MessageType
		str   string
		valid bool
	}{
		{MsgRegister, "REGISTER", true},
		{MsgBeacon, "BEACON", true},
		{MsgTask, "TASK", true},
		{MsgResult, "RESULT", true},
		{MsgShutdown, "SHUTDOWN", true},
		{MessageType(0xFF), "UNKNOWN(0xff)", false},
	}

	for _, tc := range tests {
		if got := tc.mt.String(); got != tc.str {
			t.Errorf("MessageType(0x%02x).String() = %q, want %q", byte(tc.mt), got, tc.str)
		}
		if got := tc.mt.Valid(); got != tc.valid {
			t.Errorf("MessageType(0x%02x).Valid() = %v, want %v", byte(tc.mt), got, tc.valid)
		}
	}
}

// TestFieldTypeString tests FieldType.String() for coverage.
func TestFieldTypeString(t *testing.T) {
	if got := FieldSessionID.String(); got != "SessionID" {
		t.Errorf("got %q, want SessionID", got)
	}
	if got := FieldType(0xFFFF).String(); got != "UNKNOWN(0xffff)" {
		t.Errorf("got %q for unknown field type", got)
	}
}

// TestGetFieldMissing tests helper methods when a field is not present.
func TestGetFieldMissing(t *testing.T) {
	msg := NewMessage(MsgBeacon) // no fields

	if msg.GetField(FieldHostname) != nil {
		t.Error("expected nil for missing field")
	}
	if msg.GetFieldString(FieldHostname) != "" {
		t.Error("expected empty string for missing field")
	}
	if msg.GetFieldUint32(FieldSeqNumber) != 0 {
		t.Error("expected 0 for missing uint32 field")
	}
	if msg.GetFieldUint16(FieldTaskType) != 0 {
		t.Error("expected 0 for missing uint16 field")
	}
	if msg.GetFieldUint64(FieldTimestamp) != 0 {
		t.Error("expected 0 for missing uint64 field")
	}
	if msg.GetFieldByte(FieldJitter) != 0 {
		t.Error("expected 0 for missing byte field")
	}
}

// TestGetFieldWrongSize tests helper methods when the field has wrong size.
func TestGetFieldWrongSize(t *testing.T) {
	msg := NewMessage(MsgBeacon).
		AddBytes(FieldSeqNumber, []byte{0x01, 0x02}). // 2 bytes, expect 4
		AddBytes(FieldTimestamp, []byte{0x01}).         // 1 byte, expect 8
		AddBytes(FieldTaskType, []byte{0x01, 0x02, 0x03}). // 3 bytes, expect 2
		AddBytes(FieldJitter, []byte{0x01, 0x02})      // 2 bytes, expect 1

	if msg.GetFieldUint32(FieldSeqNumber) != 0 {
		t.Error("expected 0 for wrong-size uint32 field")
	}
	if msg.GetFieldUint64(FieldTimestamp) != 0 {
		t.Error("expected 0 for wrong-size uint64 field")
	}
	if msg.GetFieldUint16(FieldTaskType) != 0 {
		t.Error("expected 0 for wrong-size uint16 field")
	}
	if msg.GetFieldByte(FieldJitter) != 0 {
		t.Error("expected 0 for wrong-size byte field")
	}
}
