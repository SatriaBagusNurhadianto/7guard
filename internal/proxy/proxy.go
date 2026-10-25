package proxy

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
	"github.com/SatriaBagusNurhadianto/7guard/internal/detector"
	"github.com/SatriaBagusNurhadianto/7guard/internal/jwtsec"
	"github.com/SatriaBagusNurhadianto/7guard/internal/ratelimit"
	"github.com/SatriaBagusNurhadianto/7guard/internal/rules"
	"github.com/SatriaBagusNurhadianto/7guard/internal/tlsconfig"
)

// Server is the 7Guard reverse proxy.
type Server struct {
	cfg      *config.Config
	rules    []rules.Rule
	det      *detector.Detector
	proxy    *httputil.ReverseProxy
	limiter  *ratelimit.Limiter
	jwtVal   *jwtsec.Validator
	tlsCfg   *tls.Config
}

// New creates a new 7Guard server.
func New(cfg *config.Config) (*Server, error) {
	rs, err := rules.LoadRules(cfg.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("loading rules from %s: %w", cfg.RulesDir, err)
	}

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL: %w", err)
	}

	rp := httputil.NewSingleHostReverseProxy(upstream)

	// Initialize JWT validator if secret is provided
	var jwtValidator *jwtsec.Validator
	if cfg.JWTSecret != "" {
		jwtValidator = jwtsec.New([]byte(cfg.JWTSecret))
	}

	// Initialize TLS config if cert files are provided
	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		tc, err := tlsconfig.NewTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("TLS config: %w", err)
		}
		tlsConfig = tc
	}

	s := &Server{
		cfg:      cfg,
		rules:    rs,
		det:      detector.New(rs),
		proxy:    rp,
		limiter:  ratelimit.New(cfg.RateLimit, cfg.RateBurst),
		jwtVal:   jwtValidator,
		tlsCfg:   tlsConfig,
	}

	rp.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host
	}

	return s, nil
}

// Run starts the HTTP server.
func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)
	mux.HandleFunc("/health", s.handleHealth)

	srv := &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	if s.tlsCfg != nil {
		srv.TLSConfig = s.tlsCfg
		log.Printf("7Guard listening on %s (TLS, profile=%s, mode=%s)", s.cfg.ListenAddr, s.cfg.Profile, s.cfg.Mode)
		return srv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}

	log.Printf("7Guard listening on %s (profile=%s, mode=%s)", s.cfg.ListenAddr, s.cfg.Profile, s.cfg.Mode)
	return srv.ListenAndServe()
}

// handleRequest processes incoming requests through the detection pipeline.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Generate request ID for tracing
	reqID := generateRequestID()
	w.Header().Set("X-Request-ID", reqID)

	// 1. Bound body size (handles chunked requests without Content-Length)
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodySize)

	// 2.5. JWT validation (if enabled)
	if s.jwtVal != nil {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", reqID)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      "missing authorization header",
				"request_id": reqID,
			})
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", reqID)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      "invalid authorization format",
				"request_id": reqID,
			})
			return
		}
		_, err := s.jwtVal.ValidateToken(parts[1])
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", reqID)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      err.Error(),
				"request_id": reqID,
			})
			return
		}
	}

	// 2. Normalize + Detect
	matches := s.det.Detect(r)

	// 3. Rate limiting (per IP + path)
	rateKey := r.RemoteAddr + ":" + r.URL.Path
	allowed, retryAfter := s.limiter.Allow(rateKey)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":       "rate limit exceeded",
			"retry_after": retryAfter,
			"request_id":  reqID,
		})
		return
	}

	// 4. Score
	score := 0
	for _, m := range matches {
		score += severityScore(m.Rule.Severity)
	}

	// 5. Log
	if len(matches) > 0 {
		logMatch(r, matches, score, s.cfg.Mode, reqID)
	}

	// 5. Decision
	threshold := 5
	if score >= threshold {
		if s.cfg.Mode == config.ModeBlock {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      "blocked by 7Guard",
				"score":      score,
				"matches":    len(matches),
				"request_id": reqID,
			})
			return
		}
	}

	// 6. Forward to upstream
	s.proxy.ServeHTTP(w, r)

	_ = start
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"profile": s.cfg.Profile,
		"mode":    s.cfg.Mode,
		"rules":   fmt.Sprintf("%d", len(s.rules)),
	})
}

func severityScore(sev string) int {
	switch sev {
	case rules.SeverityCritical:
		return 10
	case rules.SeverityHigh:
		return 5
	case rules.SeverityMedium:
		return 3
	case rules.SeverityLow:
		return 1
	default:
		return 1
	}
}

type logEntry struct {
	Timestamp string   `json:"timestamp"`
	RequestID string   `json:"request_id"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	ClientIP  string   `json:"client_ip"`
	Mode      string   `json:"mode"`
	Score     int      `json:"score"`
	Matches   int      `json:"matches"`
	Severity  string   `json:"severity"`
	Location  string   `json:"location"`
	Matched   string   `json:"matched_value"`
	Rules     []string `json:"rules"`
}

func logMatch(r *http.Request, matches []detector.Match, score int, mode string, reqID string) {
	var ruleIDs []string
	maxSeverity := ""
	firstLocation := ""
	firstMatched := ""
	for i, m := range matches {
		ruleIDs = append(ruleIDs, m.Rule.ID)
		if i == 0 {
			firstLocation = m.Location
			firstMatched = m.Matched
		}
		if severityRank(m.Rule.Severity) > severityRank(maxSeverity) {
			maxSeverity = m.Rule.Severity
		}
	}
	entry := logEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: reqID,
		Method:    r.Method,
		Path:      r.URL.Path,
		ClientIP:  r.RemoteAddr,
		Mode:      mode,
		Score:     score,
		Matches:   len(matches),
		Severity:  maxSeverity,
		Location:  firstLocation,
		Matched:   firstMatched,
		Rules:     ruleIDs,
	}
	b, _ := json.Marshal(entry)
	log.Printf("DETECT: %s", string(b))
}

func severityRank(sev string) int {
	switch sev {
	case rules.SeverityCritical:
		return 4
	case rules.SeverityHigh:
		return 3
	case rules.SeverityMedium:
		return 2
	case rules.SeverityLow:
		return 1
	default:
		return 0
	}
}

func generateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
