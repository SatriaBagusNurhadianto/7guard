package jwtsec

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Validator validates JWT tokens with algorithm confusion prevention.
type Validator struct {
	secret []byte
	// Allowed algorithms (prevents "none" and algorithm confusion)
	allowedAlgs []string
}

// New creates a JWT validator with the given secret.
// Only HS256 is allowed by default to prevent algorithm confusion.
func New(secret []byte) *Validator {
	return &Validator{
		secret:      secret,
		allowedAlgs: []string{"HS256"},
	}
}

// NewWithAlgs creates a validator with custom allowed algorithms.
func NewWithAlgs(secret []byte, algs []string) *Validator {
	return &Validator{
		secret:      secret,
		allowedAlgs: algs,
	}
}

// ValidateToken validates a JWT token string and returns claims.
func (v *Validator) ValidateToken(tokenStr string) (jwt.MapClaims, error) {
	// Parse with algorithm validation
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// CRITICAL: Validate the signing method to prevent algorithm confusion
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("missing alg header")
		}

		// Check if algorithm is in allowed list
		allowed := false
		for _, a := range v.allowedAlgs {
			if alg == a {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("algorithm %s not allowed", alg)
		}

		// Prevent "none" algorithm
		if alg == "none" {
			return nil, fmt.Errorf("none algorithm not allowed")
		}

		// For HMAC algorithms, return the secret
		if strings.HasPrefix(alg, "HS") {
			return v.secret, nil
		}

		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}, jwt.WithValidMethods(v.allowedAlgs))

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Validate expiry (jwt.Parse already validates exp/nbf by default)
	// Additional manual check for required exp
	if _, ok := claims["exp"]; !ok {
		return nil, fmt.Errorf("missing exp claim")
	}

	return claims, nil
}

// Middleware returns an HTTP middleware that validates JWT tokens.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
			return
		}

		claims, err := v.ValidateToken(parts[1])
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		// Store claims in request context (simplified for MVP)
		r.Header.Set("X-JWT-Claims", fmt.Sprintf("%v", claims))
		next.ServeHTTP(w, r)
	})
}

// IsAlgorithmAllowed checks if an algorithm is in the allowed list.
func (v *Validator) IsAlgorithmAllowed(alg string) bool {
	for _, a := range v.allowedAlgs {
		if a == alg {
			return true
		}
	}
	return false
}
