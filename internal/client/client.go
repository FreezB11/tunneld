// Package client implements the tunnel client: the process that runs on the
// user's local machine, dials out to tunneld, registers tunnels, and
// forwards incoming proxied connections to local services.
package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"tunnel/internal/config"
	"tunnel/internal/protocol"
)

// Client is a running tunnel client instance.
type Client struct {
	cfg *config.ClientConfig
}

// New builds a Client from config.
func New(cfg *config.ClientConfig) *Client {
	return &Client{cfg: cfg}
}

// Run connects to the server, registers all configured tunnels, and blocks
// serving proxied connections until ctx is cancelled or the connection is
// lost. Run does not retry internally; callers that want reconnect-on-drop
// behavior should call Run in a loop (see cmd/tunnel/main.go).
func (c *Client) Run(ctx context.Context) error {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: c.cfg.InsecureSkipVerify || c.cfg.ServerFingerprint != "",
		MinVersion:         tls.VersionTLS12,
	}

	if c.cfg.ServerFingerprint != "" {
		expected := c.cfg.ServerFingerprint
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyFingerprint(rawCerts, expected)
		}
	}

	dialer := &tls.Dialer{Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", c.cfg.Server)
	if err != nil {
		return fmt.Errorf("client: dial %s: %w", c.cfg.Server, err)
	}
	defer conn.Close()

	log.Printf("tunnel: connected to %s", c.cfg.Server)

	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.LogOutput = io.Discard
	session, err := yamux.Client(conn, yamuxCfg)
	if err != nil {
		return fmt.Errorf("client: yamux setup: %w", err)
	}
	defer session.Close()

	if err := c.handshake(session); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		session.Close()
	}()

	// Serve incoming streams: each one corresponds to a single proxied
	// connection the server accepted on one of our registered ports.
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("client: session ended: %w", err)
			}
		}
		go c.handleStream(stream)
	}
}

// handshake sends the hello message with our auth token and tunnel list,
// and waits for the server's ack.
func (c *Client) handshake(session *yamux.Session) error {
	stream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("client: open handshake stream: %w", err)
	}
	// Note: intentionally not closed here - the server keeps reading
	// hello/hello_ack on this same first stream is not required after
	// this exchange, but yamux streams are cheap and closing it early
	// could race with a slow write on some platforms, so we just let it
	// be garbage collected with the session teardown.

	reader := protocol.NewReader(stream)
	writer := protocol.NewWriter(stream)

	var tunnels []protocol.TunnelRequest
	for _, t := range c.cfg.Tunnels {
		tunnels = append(tunnels, protocol.TunnelRequest{
			Name:       t.Name,
			Type:       protocol.TunnelType(t.Type),
			LocalAddr:  t.LocalAddr,
			RemotePort: t.RemotePort,
		})
	}

	hello := protocol.HelloPayload{
		Token:      c.cfg.AuthToken,
		ClientName: c.cfg.ClientName,
		ClientVer:  "0.1.0",
		Tunnels:    tunnels,
	}
	if err := writer.WriteMsg(protocol.MsgTypeHello, hello); err != nil {
		return fmt.Errorf("client: send hello: %w", err)
	}

	env, err := reader.ReadMsg()
	if err != nil {
		return fmt.Errorf("client: read hello_ack: %w", err)
	}
	if env.Type != protocol.MsgTypeHelloAck {
		return fmt.Errorf("client: expected hello_ack, got %s", env.Type)
	}

	var ack protocol.HelloAckPayload
	if err := jsonUnmarshalPayload(env, &ack); err != nil {
		return fmt.Errorf("client: decode hello_ack: %w", err)
	}
	if !ack.OK {
		return fmt.Errorf("client: server rejected registration: %s", ack.Error)
	}

	for _, r := range ack.Results {
		if r.OK {
			log.Printf("tunnel: registered %q -> server port %d", r.Name, r.RemotePort)
		} else {
			log.Printf("tunnel: FAILED to register %q: %s", r.Name, r.Error)
		}
	}
	return nil
}

// handleStream reads the tunnel-name header off a newly opened stream,
// finds the matching local_addr, dials it, and splices bytes.
func (c *Client) handleStream(stream io.ReadWriteCloser) {
	defer stream.Close()

	name, err := readStreamHeader(stream)
	if err != nil {
		log.Printf("tunnel: read stream header failed: %v", err)
		return
	}

	var localAddr string
	for _, t := range c.cfg.Tunnels {
		if t.Name == name {
			localAddr = t.LocalAddr
			break
		}
	}
	if localAddr == "" {
		log.Printf("tunnel: received stream for unknown tunnel %q", name)
		return
	}

	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		log.Printf("tunnel: %q: dial local %s failed: %v", name, localAddr, err)
		return
	}
	defer localConn.Close()

	splice(stream, localConn)
}

func verifyFingerprint(rawCerts [][]byte, expectedHex string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("client: no server certificate presented")
	}
	sum := sha256.Sum256(rawCerts[0])
	got := hex.EncodeToString(sum[:])
	if got != expectedHex {
		return fmt.Errorf("client: server certificate fingerprint mismatch: got %s, want %s", got, expectedHex)
	}
	return nil
}
