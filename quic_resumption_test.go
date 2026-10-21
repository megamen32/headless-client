package headless

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/megamen32/headless-client/quic"
	"github.com/megamen32/headless-client/quic/http3"
	utls "github.com/refraction-networking/utls"
)

// TestQUICClientResumesTheSession checks that a second connection to the
// same origin resumes instead of sending the full handshake again, and that
// the third one resumes too.
//
// A browser that never resumes always sends the full handshake, and its
// hello never carries the pre_shared_key extension. The QUIC stack could not
// resume before: the TLS layer had nowhere to keep the session the server
// sent, so the ticket was lost with the handshake that received it.
func TestQUICClientResumesTheSession(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quic resumption test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	certificate := utls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	resumed := make(chan bool, 4)
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resumed <- r.TLS.DidResume
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{certificate}},
	}
	go func() { _ = server.Serve(pc) }()

	serverAddr := pc.LocalAddr().String()
	tlsConfig, quicConfig := ChromeWindows.QUICConfig(QUICOptions{
		Transport:          QUICHTTP3,
		InsecureSkipVerify: true,
	})
	// Two clients, one TLS configuration: the configuration carries the
	// session cache, so the second client finds the ticket the first one
	// got. They are two clients rather than two requests of one client
	// because the transport pools connections: a second request would ride
	// the first connection and there would be no second handshake at all.
	newClient := func() *http3.Transport {
		return &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig:      quicConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *utls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, serverAddr, tlsCfg, cfg)
			},
		}
	}

	// Three connections, not two. The second one resumes off the ticket of
	// the first; the third one must resume off the ticket of the second. A
	// client that can only resume once is a client that dies on the second
	// resumed handshake.
	const connections = 3
	for attempt := 0; attempt < connections; attempt++ {
		transport := newClient()
		req, _ := http.NewRequest(http.MethodGet, "https://resumption.test/", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("request %d: %v", attempt, err)
		}
		resp.Body.Close()
		transport.Close()
	}

	select {
	case first := <-resumed:
		if first {
			t.Error("the first connection claimed to be a resumed one")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server saw no request")
	}

	for attempt := 2; attempt <= connections; attempt++ {
		select {
		case again := <-resumed:
			if !again {
				t.Errorf("connection %d did not resume: the client never offered the ticket", attempt)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("the server saw no connection %d", attempt)
		}
	}
}
