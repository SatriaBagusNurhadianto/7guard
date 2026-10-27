package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SatriaBagusNurhadianto/7guard/internal/adaptive"
	"github.com/SatriaBagusNurhadianto/7guard/internal/behavioral"
	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
	"github.com/SatriaBagusNurhadianto/7guard/internal/detector"
	"github.com/SatriaBagusNurhadianto/7guard/internal/egress"
	"github.com/SatriaBagusNurhadianto/7guard/internal/jwtsec"
	"github.com/SatriaBagusNurhadianto/7guard/internal/leakage"
	"github.com/SatriaBagusNurhadianto/7guard/internal/metrics"
	"github.com/SatriaBagusNurhadianto/7guard/internal/quarantine"
	"github.com/SatriaBagusNurhadianto/7guard/internal/ratelimit"
	"github.com/SatriaBagusNurhadianto/7guard/internal/rules"
	"github.com/SatriaBagusNurhadianto/7guard/internal/tlsconfig"
	"github.com/fsnotify/fsnotify"
)

// Server is the 7Guard reverse proxy.
type Server struct {
	cfg      *config.Config
	rules    []rules.Rule
	det      *detector.Detector
	detMu    sync.RWMutex
	proxy    *httputil.ReverseProxy
	limiter  *ratelimit.Limiter
	jwtVal   *jwtsec.Validator
	tlsCfg   *tls.Config
	rulesDir string
	// Phase 4 (Maximum profile, default-off): behavioral analysis,
	// quarantine, and adaptive defense. Nil unless the corresponding
	// feature flag is enabled.
	behavioral *behavioral.Detector
	quarantine *quarantine.Quarantine
	adaptive   *adaptive.Adaptive
	// Egress control (Full+ profile, default-off).
	egress     *egress.Allowlist
	egressMode string
	// Response body inspection (Full+ profile, default-off).
	leakageScanner *leakage.Scanner
	respInspMode   string
	respInspMax    int64
	respInspTypes  []string
	onLeak         string
	replaceToken   string
	// Observability (infrastructure, default on).
	metrics *metrics.Metrics
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

	// Egress control (Full+ profile, default-off): gate outbound dials.
	var egressAllow *egress.Allowlist
	egressMode := cfg.EgressMode
	if cfg.HasFeature("egress_control") {
		al, err := egress.NewAllowlist(cfg.EgressAllowedHosts)
		if err != nil {
			return nil, fmt.Errorf("egress allowlist: %w", err)
		}
		egressAllow = al
		if egressMode == "" {
			egressMode = config.EgressModeDetect
		}
		egressAllow.Mode = egressMode
		transport := &http.Transport{
			DialContext: al.DialContext(nil),
		}
		rp.Transport = transport
	}

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

	// Response body inspection (Full+ profile, default-off).
	respInspMode := cfg.ResponseInspectionMode
	if respInspMode == "" {
		respInspMode = config.ResponseInspectionModeDetect
	}
	var leakScanner *leakage.Scanner
	respInspTypes := cfg.ResponseInspectionContentTypes
	if cfg.HasFeature("response_inspection") {
		leakScanner = leakage.New()
		if respInspTypes == nil {
			respInspTypes = cfg.ResponseInspectionContentTypes
		}
	}

	s := &Server{
		cfg:            cfg,
		rules:          rs,
		det:            detector.New(rs),
		proxy:          rp,
		limiter:        ratelimit.New(cfg.RateLimit, cfg.RateBurst),
		jwtVal:         jwtValidator,
		tlsCfg:         tlsConfig,
		rulesDir:       cfg.RulesDir,
		egress:         egressAllow,
		egressMode:     egressMode,
		leakageScanner: leakScanner,
		respInspMode:   respInspMode,
		respInspMax:    cfg.ResponseInspectionMaxBodyBytes,
		respInspTypes:  respInspTypes,
		onLeak:         cfg.OnLeak,
		replaceToken:   cfg.ReplaceToken,
	}

	// Phase 4 (Maximum profile): behavioral analysis, quarantine, adaptive
	// defense. Wired only when the profile enables the feature flags, so
	// existing behavior is unchanged by default.
	if cfg.HasFeature("behavioral_analysis") || cfg.HasFeature("attack_chain") {
		s.behavioral = behavioral.New(nil)
	}
	if cfg.HasFeature("quarantine") {
		s.quarantine = quarantine.New()
	}
	if cfg.HasFeature("adaptive_defense") {
		s.adaptive = adaptive.New(adaptive.DefaultPolicy())
	}

	// Observability (infrastructure, default on).
	if cfg.MetricsEnabled {
		s.metrics = metrics.New()
	}

	// Wire egress metrics callback.
	if s.egress != nil && s.metrics != nil {
		s.egress.OnDecision = func(allowed bool, reason string) {
			if allowed {
				s.metrics.IncEgressAllowed()
			} else {
				s.metrics.IncEgressDenied(reason)
			}
		}
	}

	rp.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host
	}
	rp.ModifyResponse = s.modifyResponse

	return s, nil
}

// Run starts the HTTP server.
func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)
	mux.HandleFunc("/health", s.handleHealth)
	if s.metrics != nil {
		if s.cfg.MetricsAuthToken != "" {
			mux.HandleFunc("/metrics", s.metricsAuthWrapper(s.metrics.Handler))
		} else {
			mux.HandleFunc("/metrics", s.metrics.Handler)
		}
	}

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

// ReloadRules reloads rules from disk and swaps the detector atomically.
// Returns the number of rules loaded, or an error (old rules are kept on failure).
func (s *Server) ReloadRules() (int, error) {
	rs, err := rules.LoadRules(s.rulesDir)
	if err != nil {
		return 0, fmt.Errorf("reload failed: %w", err)
	}

	newDet := detector.New(rs)

	s.detMu.Lock()
	s.det = newDet
	s.rules = rs
	s.detMu.Unlock()

	log.Printf("rules reloaded: %d rules", len(rs))
	return len(rs), nil
}

// StartWatcher starts a file watcher for hot-reload of rules.
// Returns a stop function to call on shutdown.
func (s *Server) StartWatcher() (func(), error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating watcher: %w", err)
	}

	if err := watcher.Add(s.rulesDir); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("watching dir %s: %w", s.rulesDir, err)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					log.Printf("rule file changed: %s, reloading...", event.Name)
					if _, err := s.ReloadRules(); err != nil {
						log.Printf("hot-reload failed (keeping old rules): %v", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("watcher error: %v", err)
			}
		}
	}()

	return func() { _ = watcher.Close() }, nil
}

// QuarantineCleanup removes expired quarantine entries. Safe to call periodically.
func (s *Server) QuarantineCleanup() {
	if s.quarantine != nil {
		s.quarantine.Cleanup()
		if s.metrics != nil {
			s.metrics.SetQuarantined(int64(s.quarantine.Size()))
		}
	}
}
func (s *Server) LimiterCleanup() {
	s.limiter.Cleanup(10 * time.Minute)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Generate request ID for tracing
	reqID := generateRequestID()
	w.Header().Set("X-Request-ID", reqID)

	// Observability: count every request (excluding scrape/health endpoints).
	if s.metrics != nil && r.URL.Path != "/metrics" && r.URL.Path != "/health" {
		s.metrics.IncRequests()
	}

	// Normalize client IP (strip ephemeral port) for quarantine/behavioral/
	// rate-limit keys so the same client is recognized across connections.
	clientIP := clientIPFromRequest(r)

	// 1. Bound body size (handles chunked requests without Content-Length)
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodySize)

	// 1.5. Quarantine check (Maximum profile, default-off)
	if s.quarantine != nil {
		if s.metrics != nil {
			s.metrics.SetQuarantined(int64(s.quarantine.Size()))
		}
		if s.quarantine.IsQuarantined(clientIP) {
			if s.metrics != nil {
				s.metrics.IncBlock("quarantine")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", reqID)
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      "quarantined by 7Guard",
				"request_id": reqID,
			})
			return
		}
	}

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
	s.detMu.RLock()
	matches := s.det.Detect(r)
	s.detMu.RUnlock()

	// Observability: count rule matches.
	if s.metrics != nil {
		for _, m := range matches {
			s.metrics.IncRuleMatch(m.Rule.ID)
		}
	}

	// 2.6. Behavioral analysis (Maximum profile, default-off): record event
	// and evaluate attack chains. Quarantine the subject on critical chains.
	if s.behavioral != nil {
		ev := behavioral.Event{
			RequestID:   reqID,
			ClientIP:    clientIP,
			Timestamp:   time.Now(),
			RuleMatches: matchIDs(matches),
			Score:       0,
			Path:        r.URL.Path,
			Method:      r.Method,
			UserAgent:   r.UserAgent(),
		}
		for _, m := range matches {
			ev.Score += severityScore(m.Rule.Severity)
		}
		alerts := s.behavioral.Record(ev)
		for _, a := range alerts {
			if a.Severity == "critical" && s.quarantine != nil {
				s.quarantine.Quarantine(clientIP, "attack-chain: "+a.ChainID, 10*time.Minute)
				if s.metrics != nil {
					s.metrics.SetQuarantined(int64(s.quarantine.Size()))
				}
			}
		}
	}

	// 3. Score (computed early so adaptive throttling can use it)
	score := 0
	for _, m := range matches {
		score += severityScore(m.Rule.Severity)
	}

	// 4. Rate limiting (per IP + path), with adaptive throttling when wired.
	mult := 1.0
	if s.adaptive != nil {
		action := s.adaptive.Evaluate(score)
		if action == adaptive.ActionThrottle {
			mult = s.adaptive.RateMultiplier(action)
		}
	}
	rateKey := clientIP + ":" + r.URL.Path
	allowed, retryAfter := s.limiter.AllowWithMultiplier(rateKey, mult)
	if !allowed {
		if s.metrics != nil {
			s.metrics.IncBlock("rate")
		}
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

	// 5. Log
	if len(matches) > 0 {
		logMatch(r, matches, score, s.cfg.Mode, reqID)
	}

	// 5. Adaptive defense (Maximum profile, default-off): adjust decision
	// based on threat score. Only affects when enabled.
	if s.adaptive != nil {
		action := s.adaptive.Evaluate(score)
		if s.metrics != nil {
			s.metrics.IncAdaptive(action.String())
		}
		if action == adaptive.ActionBlock && s.cfg.Mode == config.ModeBlock {
			if s.metrics != nil {
				s.metrics.IncBlock("adaptive")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Request-ID", reqID)
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      "blocked by adaptive defense",
				"score":      score,
				"request_id": reqID,
			})
			return
		}
	}
	if score >= 5 {
		if s.cfg.Mode == config.ModeBlock {
			if s.metrics != nil {
				s.metrics.IncBlock("waf")
			}
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
	if s.egress != nil {
		r = r.WithContext(egress.WithRequestID(r.Context(), reqID))
	}
	s.proxy.ServeHTTP(w, r)

	_ = start
}

func (s *Server) metricsAuthWrapper(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimPrefix(h, "Bearer ")
		}
		if token != s.cfg.MetricsAuthToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
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

func clientIPFromRequest(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func matchIDs(matches []detector.Match) []string {
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, m.Rule.ID)
	}
	return ids
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
		ClientIP:  clientIPFromRequest(r),
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

func (s *Server) allowedContentType(mediaType string) bool {
	for _, ct := range s.respInspTypes {
		ct = strings.TrimSpace(ct)
		if strings.HasSuffix(ct, "/*") {
			prefix := strings.TrimSuffix(ct, "*")
			if strings.HasPrefix(mediaType, prefix) {
				return true
			}
			continue
		}
		if mediaType == ct {
			return true
		}
	}
	return false
}

func (s *Server) modifyResponse(resp *http.Response) error {
	if s.leakageScanner == nil {
		return nil
	}
	// Redirects pass through unmodified.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if !s.allowedContentType(mediaType) {
		return nil
	}
	// Skip compressed responses (v1).
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		log.Printf("response inspection: skipped_compressed")
		return nil
	}
	max := s.respInspMax
	if max <= 0 {
		max = 1 << 20
	}
	prefix, err := io.ReadAll(io.LimitReader(resp.Body, max))
	if err != nil {
		_ = err
	}
	// Detect whether more data remains.
	one := make([]byte, 1)
	n, _ := resp.Body.Read(one)
	truncated := n > 0
	var remainder io.Reader
	if n > 0 {
		remainder = io.MultiReader(bytes.NewReader(one[:n]), resp.Body)
	} else {
		remainder = resp.Body
		_ = resp.Body.Close()
	}

	leaks := s.leakageScanner.Scan(prefix)
	distinct := leakage.LeakTypes(leaks)

	if len(leaks) == 0 {
		// pass through
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), remainder))
		return nil
	}

	// Distinct types -> metric (once per response per type).
	if s.metrics != nil {
		for _, t := range distinct {
			s.metrics.IncResponseLeak(t)
		}
	}

	// Detect mode: allow + log + metric.
	if s.respInspMode != config.ModeBlock {
		log.Printf("response leak detected: types=%v status=%d content_type=%s truncated=%v", distinct, resp.StatusCode, mediaType, truncated)
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), remainder))
		return nil
	}

	// Block mode.
	switch s.onLeak {
	case config.OnLeakBlock:
		resp.StatusCode = http.StatusBadGateway
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		resp.Header.Del("Content-Length")
		return nil
	case config.OnLeakStrip, config.OnLeakReplace:
		strip := s.onLeak == config.OnLeakStrip
		token := s.replaceToken
		if strip {
			token = ""
		}
		redacted := leakage.Redact(prefix, leaks, token, strip)
		if !truncated && remainder == nil {
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(redacted)))
		} else {
			// modified or truncated: drop Content-Length to allow chunked
			resp.Header.Del("Content-Length")
		}
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(redacted), remainder))
		return nil
	}
	return nil
}
