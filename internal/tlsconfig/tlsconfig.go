package tlsconfig

import (
	"crypto/tls"
	"fmt"
)

// MinTLSVersion is the minimum TLS version (TLS 1.2).
const MinTLSVersion = tls.VersionTLS12

// StrongCipherSuites returns a list of strong cipher suites (no RC4, 3DES, etc.).
func StrongCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// NewTLSConfig creates a secure TLS configuration.
func NewTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   MinTLSVersion,
		CipherSuites: StrongCipherSuites(),
		// Prevent renegotiation attacks
		Renegotiation: tls.RenegotiateNever,
	}, nil
}

// IsWeakCipher checks if a cipher suite is considered weak.
func IsWeakCipher(cipher uint16) bool {
	weak := map[uint16]bool{
		tls.TLS_RSA_WITH_RC4_128_SHA:      true,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA: true,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:  true,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:  true,
	}
	return weak[cipher]
}
