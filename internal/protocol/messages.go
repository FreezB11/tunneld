package protocol
// this here will be used to define the controlplane wire format
// that will be exchanges btw the tunneld and client

import(
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

type MsgType string // identity the msg type

const(
	// hello msg is sent from the client after connection
	// it carries the auth token and list of tunnels client wants to register
	Hello MsgType = "hello"

	// this will be the reply to the above. on success it will echo
	// back the tunnels that are registered,
	// on failure, ERROR is set and the connnection will be closed  @todo-> will maybe give a dedicated return msg on failure will see
	Ack MsgType = "hello_ack"

	// now we will do a health check, heartbeatssss
	Ping MsgType = "ping"
	Pong MsgType = "pong"
)

// now the distinction is done for logging purpose as for debugging later it will be usefull and 
// later we will add different behaviour to this 
type TunnelType string

const (
	TunnelTCP	TunnelType  = "tcp"
	TunnelHTTP	TunnelType	= "http"
)

// TunnelRequest is one tunnel the client wants the server to expose.
type TunnelRequest struct{
	Name 		string 		`json:"name"`
	Type 		TunnelType	`json:"type"`
	LocalAddr	string		`json:"local_addr"` //eg 127.0.0.1:3000
	RemotePort	int 		`json:"remote_port"` // port to bind on the server's public ip
}

// TunnelResult is the server's response for one requested tunnel.
type TunnelResponse struct{
	Name		string	`json:"name"`
	RemotePort	string	`json:"remote_port"`
	OK 			string	`json:"ok"`
	Error 		string	`json:"error,omitempty"`
}

// HelloPayload is the body of a Hello message.
type HelloPayload struct {
	Token      string          `json:"token"`
	ClientName string          `json:"client_name"`
	ClientVer  string          `json:"client_version"`
	Tunnels    []TunnelRequest `json:"tunnels"`
}
 
// HelloAckPayload is the body of a Ack message.
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

// wraps io.writter and encode newline-delimited json envelops
type Writer struct{
	w io.Writer
}

func NewWriter(w io.Writer) *Writer{
	reutrn &Writer{w: w}
}

//this marshals the payload, wraps it in envelope of the given type, and writes
//it followed by a newline.
func(cw *Writer)  Writer(t MsgType, payload interfave{}) error{
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil{
			return fmt.Errorf("protocol: marshal payload: %w", err)
		}
		raw = b
	}
	env := Envelope{Type: t, Payload: raw}
	b, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("protocol: marshall envelope: %w", err)
	}
	b = append(b, '\n')
	_, err = cw.w.write(b)
	return err
}

// Reader wraps a bufio.Reader and decodes newline-delimited JSON envelopes.
type Reader struct {
	r *bufio.Reader
}
 
func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReader(r)}
}

//reads one newline-delimited Envelope. The caller should type-switch
//on the returned Envelope.Type and unmarshal Envelope.Payload accordingly.
func (cr *Reader) ReadMsg() (Envelope, error) {
	line, err := cr.r.ReadBytes('\n')
	if err != nil {
		//If we got a partial line before EOF, it's still an error
		//well-formed envelope always(shud) ends with '\n'.
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Envelope{}, fmt.Errorf("protocol: decode envelope: %w", err)
	}
	return env, nil
}