package jwtsec

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateTokenValid(t *testing.T) {
	secret := []byte("test-secret-key")
	v := New(secret)

	// Create a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	tokenStr, _ := token.SignedString(secret)

	claims, err := v.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims["sub"] != "user1" {
		t.Errorf("wrong subject: %v", claims["sub"])
	}
}

func TestValidateTokenExpired(t *testing.T) {
	secret := []byte("test-secret-key")
	v := New(secret)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user1",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	})
	tokenStr, _ := token.SignedString(secret)

	_, err := v.ValidateToken(tokenStr)
	if err == nil {
		t.Error("expired token should be rejected")
	}
}

func TestValidateTokenMissingExp(t *testing.T) {
	secret := []byte("test-secret-key")
	v := New(secret)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user1",
	})
	tokenStr, _ := token.SignedString(secret)

	_, err := v.ValidateToken(tokenStr)
	if err == nil {
		t.Error("token without exp should be rejected")
	}
}

func TestAlgorithmConfusionNone(t *testing.T) {
	secret := []byte("test-secret-key")
	v := New(secret)

	// Create a token with "none" algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "admin",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	tokenStr, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	_, err := v.ValidateToken(tokenStr)
	if err == nil {
		t.Error("none algorithm token should be rejected")
	}
}

func TestAlgorithmConfusionHS256WithRSAPublicKey(t *testing.T) {
	secret := []byte("test-secret-key")
	v := New(secret)

	// Token signed with a different secret should fail
	wrongSecret := []byte("wrong-secret")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "admin",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	tokenStr, _ := token.SignedString(wrongSecret)

	_, err := v.ValidateToken(tokenStr)
	if err == nil {
		t.Error("token signed with wrong secret should be rejected")
	}
}

func TestIsAlgorithmAllowed(t *testing.T) {
	v := New([]byte("secret"))

	if !v.IsAlgorithmAllowed("HS256") {
		t.Error("HS256 should be allowed")
	}
	if v.IsAlgorithmAllowed("none") {
		t.Error("none should not be allowed")
	}
	if v.IsAlgorithmAllowed("RS256") {
		t.Error("RS256 should not be allowed (not in allowed list)")
	}
}

func TestMiddlewareMissingAuth(t *testing.T) {
	v := New([]byte("secret"))
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareInvalidFormat(t *testing.T) {
	v := New([]byte("secret"))
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareValidToken(t *testing.T) {
	secret := []byte("test-secret-key")
	v := New(secret)
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	tokenStr, _ := token.SignedString(secret)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
