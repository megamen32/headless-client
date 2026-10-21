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

// TestQUICConnectionsCarryTheirOwnServerName checks that two connections of
// one client carry their own server name.
//
// uTLS takes the name of the handshake from the spec's SNI extension, and
// the spec is shared between the connections of a client: without a copy per
// connection the second connection to another host would carry the first
// one's name — and fail.
func TestQUICConnectionsCarryTheirOwnServerName(t *testing.T) {
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

	seen := make(chan string, 4)
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen <- r.TLS.ServerName
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{certificate}},
	}
	go func() { _ = server.Serve(pc) }()

	tlsConfig, quicConfig := ChromeWindows.QUICConfig(QUICOptions{
		Transport:          QUICHTTP3,
		InsecureSkipVerify: true,
	})
	serverAddr := pc.LocalAddr().String()
	transport := &http3.Transport{
		QUICConfig:      quicConfig,
		TLSClientConfig: tlsConfig,
		// The dialer ignores the name and goes to the local server: the
		// name still rides in the TLS config, which is the point.
		Dial: func(ctx context.Context, addr string, tlsCfg *utls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, serverAddr, tlsCfg, cfg)
		},
	}
	defer transport.Close()

	names := []string{"first.test", "second.test"}
	for _, name := range names {
		req, _ := http.NewRequest(http.MethodGet, "https://"+name+"/", nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("request %s: %v", name, err)
		}
		resp.Body.Close()
	}

	got := map[string]bool{}
	for range names {
		select {
		case name := <-seen:
			got[name] = true
		case <-time.After(5 * time.Second):
			t.Fatal("the server saw no request")
		}
	}
	for _, name := range names {
		if !got[name] {
			t.Errorf("the server saw %v, the connection to %s did not carry its own name", got, name)
		}
	}
}
