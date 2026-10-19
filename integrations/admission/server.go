package admission

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"
)

// certReloader serves a key pair from disk and reloads it when the files
// change, so certificates rotated by cert-manager take effect without a
// restart.
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	checked time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.get(nil); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && time.Since(r.checked) < 10*time.Second {
		return r.cert, nil
	}
	r.checked = time.Now()
	info, err := os.Stat(r.certFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil // keep serving the last good certificate
		}
		return nil, err
	}
	if r.cert != nil && !info.ModTime().After(r.modTime) {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil // mid-rotation; retry on a later handshake
		}
		return nil, err
	}
	r.cert, r.modTime = &cert, info.ModTime()
	return r.cert, nil
}

// Serve runs the webhook over HTTPS until ctx is cancelled.
func Serve(ctx context.Context, addr, certFile, keyFile string, h http.Handler) error {
	reloader, err := newCertReloader(certFile, keyFile)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/validate", h)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: reloader.get},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			return err
		}
		if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
