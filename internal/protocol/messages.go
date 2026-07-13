// Package protocol defines the control-plane wire format exchanged between
// the tunnel client and the tunneld server over the control connection.
//
// Wire format: every message is a single JSON object, newline-delimited,
// written to the control stream. JSON keeps this human-debuggable (you can
// literally `nc` the control port and read what's happening) at the cost of
// a little efficiency, which does not matter here since control messages are
// rare compared to the actual proxied data (which never touches this codec).
package protocol

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// MsgType identifies the kind of control message.
type MsgType string

const (
	// MsgTypeHello is sent by the client immediately after connecting.
	// It carries the auth token and the list of tunnels the client wants
	// to register.
	MsgTypeHello MsgType = "hello"

	// MsgTypeHelloAck is the server's reply to MsgTypeHello. On success it
	// echoes back the tunnels that were actually registered (which may
	// have server-assigned ports if the client requested port 0 / "any").
	// On failure Error is set and the connection should be closed.
	MsgTypeHelloAck MsgType = "hello_ack"

	// MsgTypePing / MsgTypePong are a simple heartbeat so both sides can
	// detect a dead connection faster than the OS-level TCP timeout.
	MsgTypePing MsgType = "ping"
	MsgTypePong MsgType = "pong"
)

// TunnelType distinguishes how the server should treat traffic for a tunnel.
// In v1 both types behave identically at the byte level (the server does not
// parse HTTP) - the distinction exists so config and logging are meaningful,
// and so a future version can make "http" Host-header-routed without
// changing the wire format.
type TunnelType string

const (
	TunnelTCP  TunnelType = "tcp"
	TunnelHTTP TunnelType = "http"
)

// TunnelRequest is one tunnel the client wants the server to expose.
type TunnelRequest struct {
	Name       string     `json:"name"`
	Type       TunnelType `json:"type"`
	LocalAddr  string     `json:"local_addr"`  // e.g. "127.0.0.1:3000"
	RemotePort int        `json:"remote_port"` // port to bind on the server's public interface
}

// TunnelResult is the server's response for one requested tunnel.
type TunnelResult struct {
	Name       string `json:"name"`
	RemotePort int    `json:"remote_port"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// HelloPayload is the body of a MsgTypeHello message.
type HelloPayload struct {
	Token      string          `json:"token"`
	ClientName string          `json:"client_name"`
	ClientVer  string          `json:"client_version"`
	Tunnels    []TunnelRequest `json:"tunnels"`
}

// HelloAckPayload is the body of a MsgTypeHelloAck message.
type HelloAckPayload struct {
	OK      bool           `json:"ok"`
	Error   string         `json:"error,omitempty"`
	Results []TunnelResult `json:"results,omitempty"`
}

// Envelope is the outer JSON object every control message is wrapped in.
// Payload is re-marshaled/unmarshaled based on Type by the caller.
type Envelope struct {
	Type    MsgType         `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Writer wraps an io.Writer and encodes newline-delimited JSON envelopes.
type Writer struct {
	w io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// WriteMsg marshals payload, wraps it in an Envelope of the given type, and
// writes it followed by a newline.
func (cw *Writer) WriteMsg(t MsgType, payload interface{}) error {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("protocol: marshal payload: %w", err)
		}
		raw = b
	}
	env := Envelope{Type: t, Payload: raw}
	b, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("protocol: marshal envelope: %w", err)
	}
	b = append(b, '\n')
	_, err = cw.w.Write(b)
	return err
}

// Reader wraps a bufio.Reader and decodes newline-delimited JSON envelopes.
type Reader struct {
	r *bufio.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReader(r)}
}

// ReadMsg reads one newline-delimited Envelope. The caller should type-switch
// on the returned Envelope.Type and unmarshal Envelope.Payload accordingly.
func (cr *Reader) ReadMsg() (Envelope, error) {
	line, err := cr.r.ReadBytes('\n')
	if err != nil {
		// If we got a partial line before EOF, it's still an error - a
		// well-formed envelope always ends with '\n'.
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Envelope{}, fmt.Errorf("protocol: decode envelope: %w", err)
	}
	return env, nil
}
