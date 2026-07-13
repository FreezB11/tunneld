package server

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

// writeStreamHeader writes a length-prefixed tunnel name as the first bytes
// of a freshly opened yamux stream, so the client knows which local_addr to
// dial for this particular proxied connection. Format: uint16 length (big
// endian) followed by that many bytes of UTF-8 tunnel name.
//
// This is deliberately a tiny binary framing rather than another JSON
// envelope: it runs once per proxied TCP connection (potentially very high
// volume), so keeping it to a handful of bytes matters more here than
// readability.
func writeStreamHeader(w io.Writer, tunnelName string) error {
	name := []byte(tunnelName)
	if len(name) > 65535 {
		return fmt.Errorf("tunnel name too long")
	}
	hdr := make([]byte, 2+len(name))
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(name)))
	copy(hdr[2:], name)
	_, err := w.Write(hdr)
	return err
}

// readStreamHeader is the client-side counterpart of writeStreamHeader.
func readStreamHeader(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	nameBuf := make([]byte, n)
	if _, err := io.ReadFull(r, nameBuf); err != nil {
		return "", err
	}
	return string(nameBuf), nil
}

// splice copies bytes bidirectionally between a and b until either side
// closes or errors, then ensures both are closed. Used to bridge a public
// internet connection and the yamux stream carrying it back to the client
// (server side), and separately to bridge a yamux stream and the local
// service connection (client side).
func splice(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(a, b)
		a.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		b.Close()
	}()

	wg.Wait()
}

// hostOf extracts just the host/IP portion of a net.Addr, defensively
// handling the case where SplitHostPort fails (shouldn't happen for real
// TCP addrs, but better than panicking).
func hostOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func jsonUnmarshal(raw json.RawMessage, v interface{}) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty payload")
	}
	return json.Unmarshal(raw, v)
}
