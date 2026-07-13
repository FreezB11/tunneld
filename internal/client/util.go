package client

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"tunnel/internal/protocol"
)

// readStreamHeader is the client-side counterpart of the server's
// writeStreamHeader (see internal/server/util.go for the wire format
// this mirrors: uint16 big-endian length + UTF-8 tunnel name).
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
// closes or errors.
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

func jsonUnmarshalPayload(env protocol.Envelope, v interface{}) error {
	if len(env.Payload) == 0 {
		return fmt.Errorf("empty payload")
	}
	return json.Unmarshal(env.Payload, v)
}
