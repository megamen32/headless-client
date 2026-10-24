package websocket

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// TestClientAcceptsServerDeflateWithoutNctFlags proves the dialer survives
// the MAX edge answer: a 101 with permessage-deflate that carries neither
// no_context_takeover flag. Chrome accepts that answer and keeps sending
// uncompressed frames while still decompressing what the server sends; the
// vendored client used to fail the whole handshake with "invalid
// compression negotiation".
//
// The server here answers the way ws-api.oneme.ru answers a real Chrome
// (measured 2026-10-24): "permessage-deflate; client_max_window_bits=14",
// no takeover flags, and it compresses its own messages.
func TestClientAcceptsServerDeflateWithoutNctFlags(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	served := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		key := ""
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			if name, value, found := strings.Cut(line, ":"); found && strings.EqualFold(name, "Sec-WebSocket-Key") {
				key = strings.TrimSpace(value)
			}
		}
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + computeAcceptKey(key) + "\r\n" +
			"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=14\r\n\r\n"
		if _, err := connection.Write([]byte(response)); err != nil {
			return
		}
		close(served)

		// The MAX edge compresses its own frames (context takeover on its
		// side) and must read the client's masked ones as the server.
		conn := newConn(connection, true, 1024, 1024, nil, nil, nil)
		conn.newDecompressionReader = decompressNoContextTakeover
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if messageType != TextMessage {
			return
		}
		// Echo back the way a context-takeover server does: through
		// NextWriter, which compresses because the negotiated extension
		// armed the writer.
		w, err := conn.NextWriter(messageType)
		if err != nil {
			return
		}
		_, _ = w.Write(data)
		_ = w.Close()
	}()

	dialer := Dialer{HandshakeTimeout: 5 * time.Second}
	// The client offers permessage-deflate the way mimic's upgrade header
	// does; EnableCompression stays false so the client's own frames stay
	// plain — the exact shape mimic produces.
	connection, _, err := dialer.Dial("ws://"+listener.Addr().String()+"/",
		map[string][]string{
			"Origin":                  {"https://web.max.ru"},
			"Sec-WebSocket-Extensions": {"permessage-deflate; client_max_window_bits"},
		})
	if err != nil {
		t.Fatalf("dial against a MAX-shaped 101 failed: %v", err)
	}
	defer connection.Close()
	<-served

	if err := connection.WriteMessage(TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write after handshake: %v", err)
	}
	_, data, err := connection.ReadMessage()
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(data) != "ping" {
		t.Fatalf("echo: got %q, want ping", data)
	}
}
