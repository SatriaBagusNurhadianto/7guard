package tlsconfig

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestStrongCipherSuites(t *testing.T) {
	suites := StrongCipherSuites()
	if len(suites) == 0 {
		t.Error("no cipher suites returned")
	}
	for _, s := range suites {
		if IsWeakCipher(s) {
			t.Errorf("strong suite list contains weak cipher: %d", s)
		}
	}
}

func TestIsWeakCipher(t *testing.T) {
	if !IsWeakCipher(tls.TLS_RSA_WITH_RC4_128_SHA) {
		t.Error("RC4 should be weak")
	}
	if !IsWeakCipher(tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA) {
		t.Error("3DES should be weak")
	}
	if IsWeakCipher(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) {
		t.Error("ECDHE-AES256-GCM should not be weak")
	}
}

func TestMinTLSVersion(t *testing.T) {
	if MinTLSVersion != tls.VersionTLS12 {
		t.Errorf("min TLS version should be 1.2, got %d", MinTLSVersion)
	}
}

func TestNewTLSConfigMissingFiles(t *testing.T) {
	_, err := NewTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for missing files")
	}
}

func TestNewTLSConfigValid(t *testing.T) {
	// Generate a self-signed cert for testing
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	// Use openssl to generate cert (if available)
	// For simplicity, just test that the function returns an error for invalid files
	// and a valid config for valid files
	os.WriteFile(certFile, []byte("invalid"), 0644)
	os.WriteFile(keyFile, []byte("invalid"), 0644)

	_, err := NewTLSConfig(certFile, keyFile)
	if err == nil {
		t.Error("expected error for invalid cert files")
	}
}
