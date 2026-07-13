// Package server implements tunneld: the process that runs on the EC2 box,
// accepts client control connections, and exposes registered tunnels on
// public ports.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/hashicorp/yamux"

	"tunnel/internal/auth"
	"tunnel/internal/config"
	"tunnel/internal/protocol"
)

// Server is a running tunneld instance.
type Server struct {
	cfg  *config.ServerConfig
	auth auth.Authenticator
	acl  *aclChecker

	mu       sync.Mutex
	sessions map[string]*clientSession // keyed by tunnel name -> owning session
	ports    map[int]net.Listener      // keyed by remote port -> public listener
}

// clientSession represents one connected client and its yamux session.
type clientSession struct {
	identity auth.Identity
	yamuxSes *yamux.Session
	tunnels  []protocol.TunnelRequest
}

// New builds a Server from config. It does not start listening; call Run.
func New(cfg *config.ServerConfig, authenticator auth.Authenticator) (*Server, error) {
	acl, err := newACLChecker(cfg.ACL)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		auth:     authenticator,
		acl:      acl,
		sessions: make(map[string]*clientSession),
		ports:    make(map[int]net.Listener),
	}, nil
}

// Run starts the control listener and blocks, accepting client connections
// until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	var tlsCert tls.Certificate
	var err error

	if s.cfg.TLS.CertFile != "" && s.cfg.TLS.KeyFile != "" {
		tlsCert, err = tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("server: load tls cert/key: %w", err)
		}
		log.Printf("tunneld: using configured TLS certificate")
	} else {
		var fingerprint string
		tlsCert, fingerprint, err = generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("server: generate self-signed cert: %w", err)
		}
		log.Printf("tunneld: generated self-signed TLS certificate")
		log.Printf("tunneld: fingerprint (put this in client config as server_fingerprint): %s", fingerprint)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", s.cfg.ListenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("server: listen on %s: %w", s.cfg.ListenAddr, err)
	}
	defer ln.Close()

	log.Printf("tunneld: control listener on %s", s.cfg.ListenAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("tunneld: accept error: %v", err)
				continue
			}
		}
		go s.handleControlConn(ctx, conn)
	}
}

// handleControlConn processes one client's control connection: auth
// handshake, tunnel registration, then blocks routing yamux streams until
// the client disconnects.
func (s *Server) handleControlConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remoteIP := hostOf(conn.RemoteAddr())
	log.Printf("tunneld: control connection from %s", conn.RemoteAddr())

	// Wrap the raw connection in yamux immediately. The first logical
	// stream carries the JSON handshake; after that we only read new
	// streams to dial out to local services.
	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.LogOutput = io.Discard
	session, err := yamux.Server(conn, yamuxCfg)
	if err != nil {
		log.Printf("tunneld: yamux setup failed for %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer session.Close()

	handshakeStream, err := session.Accept()
	if err != nil {
		log.Printf("tunneld: handshake stream failed for %s: %v", conn.RemoteAddr(), err)
		return
	}

	reader := protocol.NewReader(handshakeStream)
	writer := protocol.NewWriter(handshakeStream)

	env, err := reader.ReadMsg()
	if err != nil {
		log.Printf("tunneld: read hello from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if env.Type != protocol.MsgTypeHello {
		log.Printf("tunneld: expected hello from %s, got %s", conn.RemoteAddr(), env.Type)
		return
	}

	var hello protocol.HelloPayload
	if err := unmarshalPayload(env, &hello); err != nil {
		log.Printf("tunneld: decode hello from %s: %v", conn.RemoteAddr(), err)
		return
	}

	identity, err := s.auth.Authenticate(ctx, hello.Token, hello.ClientName)
	if err != nil {
		log.Printf("tunneld: auth failed for %s (client %q): %v", conn.RemoteAddr(), hello.ClientName, err)
		_ = writer.WriteMsg(protocol.MsgTypeHelloAck, protocol.HelloAckPayload{
			OK: false, Error: "authentication failed",
		})
		return
	}

	results, sess, err := s.registerTunnels(identity, hello.Tunnels, session)
	if err != nil {
		log.Printf("tunneld: register tunnels for %s: %v", identity.ClientName, err)
		_ = writer.WriteMsg(protocol.MsgTypeHelloAck, protocol.HelloAckPayload{
			OK: false, Error: err.Error(),
		})
		return
	}
	defer s.teardownSession(sess)

	if err := writer.WriteMsg(protocol.MsgTypeHelloAck, protocol.HelloAckPayload{
		OK: true, Results: results,
	}); err != nil {
		log.Printf("tunneld: write hello_ack to %s: %v", identity.ClientName, err)
		return
	}

	log.Printf("tunneld: client %q registered %d tunnel(s) from %s", identity.ClientName, len(results), remoteIP)

	// Block here until the session dies (client disconnect, network
	// failure, etc). Streams for proxied connections are opened
	// on-demand elsewhere (in the per-port accept loop) via
	// session.OpenStream(), not here.
	<-session.CloseChan()
	log.Printf("tunneld: client %q disconnected", identity.ClientName)
}

// registerTunnels validates and opens public listeners for each requested
// tunnel, rolling back any partial registration on failure.
func (s *Server) registerTunnels(identity auth.Identity, reqs []protocol.TunnelRequest, session *yamux.Session) ([]protocol.TunnelResult, *clientSession, error) {
	if len(reqs) == 0 {
		return nil, nil, fmt.Errorf("no tunnels requested")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess := &clientSession{identity: identity, yamuxSes: session}
	var results []protocol.TunnelResult
	var openedPorts []int

	rollback := func() {
		for _, p := range openedPorts {
			if ln, ok := s.ports[p]; ok {
				ln.Close()
				delete(s.ports, p)
			}
		}
		for _, r := range reqs {
			delete(s.sessions, r.Name)
		}
	}

	for _, req := range reqs {
		if _, exists := s.sessions[req.Name]; exists {
			rollback()
			return nil, nil, fmt.Errorf("tunnel name %q is already registered", req.Name)
		}
		if !s.cfg.InRange(req.RemotePort) {
			rollback()
			return nil, nil, fmt.Errorf("tunnel %q: port %d outside allowed range %d-%d",
				req.Name, req.RemotePort, s.cfg.AllowedPortRange.Min, s.cfg.AllowedPortRange.Max)
		}
		if _, taken := s.ports[req.RemotePort]; taken {
			rollback()
			return nil, nil, fmt.Errorf("tunnel %q: port %d already in use", req.Name, req.RemotePort)
		}

		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", req.RemotePort))
		if err != nil {
			rollback()
			return nil, nil, fmt.Errorf("tunnel %q: bind port %d: %w", req.Name, req.RemotePort, err)
		}

		s.ports[req.RemotePort] = ln
		openedPorts = append(openedPorts, req.RemotePort)
		s.sessions[req.Name] = sess
		sess.tunnels = append(sess.tunnels, req)

		go s.acceptPublicConns(req, ln, session)

		results = append(results, protocol.TunnelResult{
			Name: req.Name, RemotePort: req.RemotePort, OK: true,
		})
		log.Printf("tunneld: tunnel %q -> public port %d (client-local %s)", req.Name, req.RemotePort, req.LocalAddr)
	}

	return results, sess, nil
}

// acceptPublicConns is the accept loop for one tunnel's public listener. For
// every accepted connection it opens a new yamux stream on the owning
// client's session and splices bytes in both directions.
func (s *Server) acceptPublicConns(req protocol.TunnelRequest, ln net.Listener, session *yamux.Session) {
	for {
		publicConn, err := ln.Accept()
		if err != nil {
			// Listener was closed (client disconnected / server
			// shutting down) - exit quietly.
			return
		}

		remoteIP := hostOf(publicConn.RemoteAddr())
		ip := net.ParseIP(remoteIP)
		if ip == nil || !s.acl.Allowed(ip) {
			log.Printf("tunneld: tunnel %q: rejecting connection from %s (ACL)", req.Name, remoteIP)
			publicConn.Close()
			continue
		}

		go func() {
			defer publicConn.Close()

			stream, err := session.OpenStream()
			if err != nil {
				log.Printf("tunneld: tunnel %q: open stream failed: %v", req.Name, err)
				return
			}
			defer stream.Close()

			// Tell the client which local_addr to dial by sending the
			// tunnel name as a single length-prefixed frame at the start
			// of the stream. Simple and avoids a second control
			// round-trip per connection.
			if err := writeStreamHeader(stream, req.Name); err != nil {
				log.Printf("tunneld: tunnel %q: write stream header failed: %v", req.Name, err)
				return
			}

			splice(publicConn, stream)
		}()
	}
}

// teardownSession removes a disconnected client's tunnels and closes their
// public listeners.
func (s *Server) teardownSession(sess *clientSession) {
	if sess == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range sess.tunnels {
		if ln, ok := s.ports[t.RemotePort]; ok {
			ln.Close()
			delete(s.ports, t.RemotePort)
		}
		delete(s.sessions, t.Name)
		log.Printf("tunneld: tunnel %q torn down", t.Name)
	}
}

func unmarshalPayload(env protocol.Envelope, v interface{}) error {
	return jsonUnmarshal(env.Payload, v)
}
