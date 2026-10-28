package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
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
	"github.com/SatriaBagusNurhadianto/7guard/internal/ssrf"
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
	leakage *leakage.Scanner
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

	if rp.Transport == nil {
		rp.Transport = &http.Transport{DisableCompression: true}
	}

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
			DialContext:        al.DialContext(nil),
			DisableCompression: true,
		}
		rp.Transport = transport
	}

	// SSRF protection (Standard+ profile): validate outbound dials against
	// blocked ranges. Wraps the egress transport so SSRF check runs first.
	if cfg.HasFeature("ssrf_basic") && cfg.SSRFMode != "off" {
		if t, ok := rp.Transport.(*http.Transport); ok {
			baseDial := t.DialContext
			if baseDial == nil {
				baseDial = (&net.Dialer{}).DialContext
			}
			mode := cfg.SSRFMode
			allowSet := map[string]bool{}
			for _, h := range cfg.SSRFAllowedHosts {
				allowSet[strings.ToLower(strings.TrimSpace(h))] = true
			}
			t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, _ := net.SplitHostPort(address)
				if host == "" {
					host = address
					port = ""
				}
				if allowSet[strings.ToLower(host)] {
					return baseDial(ctx, network, address)
				}
				ip, err := ssrf.CheckEx(host, cfg.SSRFBlockMetadata)
				if err != nil {
					log.Printf("SSRF: blocked host=%s reason=blocked_range mode=%s", host, mode)
					if mode == config.EgressModeBlock {
						return nil, fmt.Errorf("ssrf: %w", err)
					}
					// detect: log but proceed with original address
					return baseDial(ctx, network, address)
				}
				// Dial the resolved IP, not the hostname (prevent DNS rebinding).
				dialAddr := address
				if ip != nil {
					if port != "" {
						dialAddr = net.JoinHostPort(ip.String(), port)
					} else {
						dialAddr = ip.String()
					}
				}
				return baseDial(ctx, network, dialAddr)
			}
			rp.Transport = t
		}
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

	s := &Server{
		cfg:        cfg,
		rules:      rs,
		det:        detector.New(rs),
		proxy:      rp,
		limiter:    ratelimit.New(cfg.RateLimit, cfg.RateBurst),
		jwtVal:     jwtValidator,
		tlsCfg:     tlsConfig,
		rulesDir:   cfg.RulesDir,
		egress:     egressAllow,
		egressMode: egressMode,
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

	// Response body inspection (Full+ profile, default-off): scan response bodies
	// for data leakage (PII, secrets, error pages).
	if cfg.HasFeature("response_inspection") {
		scanner := leakage.New()
		s.leakage = scanner
		rp.ModifyResponse = func(resp *http.Response) error {
			if resp.Body == nil {
				return nil
			}
			ct := resp.Header.Get("Content-Type")
			mediaType, _, _ := mime.ParseMediaType(ct)
			// Content-Type gating applies to compressed responses too.
			if !contentTypeAllowed(cfg, mediaType) {
				// Redirects pass through unmodified regardless.
				if !(resp.StatusCode >= 300 && resp.StatusCode < 400) {
					return nil
				}
			}
			if ce := resp.Header.Get("Content-Encoding"); ce != "" {
				encodings := []string{}
				for _, e := range strings.Split(ce, ",") {
					e = strings.TrimSpace(strings.ToLower(e))
					if e != "" {
						encodings = append(encodings, e)
					}
				}
				if !cfg.ResponseInspectionDecompress || len(encodings) != 1 {
					if len(encodings) > 1 {
						log.Printf("RESPONSE_LEAK: skipped_multi_encoding status=%d content_encoding=%s", resp.StatusCode, ce)
					} else {
						log.Printf("RESPONSE_LEAK: skipped_compressed status=%d content_encoding=%s", resp.StatusCode, ce)
					}
					return nil
				}
				enc := encodings[0]
				maxBytes := cfg.ResponseInspectionMaxBodyBytes
				if maxBytes <= 0 {
					maxBytes = 1 << 20
				}
				maxCompressed := maxBytes * 10
				if maxCompressed < 1<<20 {
					maxCompressed = 1 << 20
				}
				compBytes, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxCompressed)+1))
				if err != nil {
					log.Printf("RESPONSE_LEAK: skipped_corrupt status=%d content_encoding=%s err=%v", resp.StatusCode, ce, err)
					resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(compBytes), resp.Body))
					resp.Header.Set("Content-Encoding", ce)
					return nil
				}
				if len(compBytes) > int(maxCompressed) {
					log.Printf("RESPONSE_LEAK: skipped_oversized status=%d content_encoding=%s", resp.StatusCode, ce)
					resp.Body = &closingReader{r: io.MultiReader(bytes.NewReader(compBytes), resp.Body), c: resp.Body}
					resp.Header.Set("Content-Encoding", ce)
					return nil
				}
				_ = resp.Body.Close()
				var decReader io.Reader
				var cleanup func()
				switch enc {
				case "gzip":
					gr, err := gzip.NewReader(bytes.NewReader(compBytes))
					if err != nil {
						log.Printf("RESPONSE_LEAK: skipped_corrupt status=%d content_encoding=%s err=%v", resp.StatusCode, ce, err)
						resp.Body = io.NopCloser(bytes.NewReader(compBytes))
						resp.Header.Set("Content-Encoding", ce)
						return nil
					}
					decReader = gr
					cleanup = func() { _ = gr.Close() }
				case "deflate":
					fr := flate.NewReader(bytes.NewReader(compBytes))
					decReader = fr
					cleanup = func() { _ = fr.Close() }
				default:
					log.Printf("RESPONSE_LEAK: skipped_compressed status=%d content_encoding=%s", resp.StatusCode, ce)
					resp.Body = io.NopCloser(bytes.NewReader(compBytes))
					resp.Header.Set("Content-Encoding", ce)
					return nil
				}
				maxBytes = cfg.ResponseInspectionMaxBodyBytes
				if maxBytes <= 0 {
					maxBytes = 1 << 20
				}
				decBytes, rerr := io.ReadAll(io.LimitReader(decReader, maxBytes+1))
				if cleanup != nil {
					cleanup()
				}
				truncated := len(decBytes) > int(maxBytes)
				if truncated {
					decBytes = decBytes[:maxBytes]
				}
				if len(compBytes) > 0 && len(decBytes) > 0 {
					ratio := float64(len(decBytes)) / float64(len(compBytes))
					if ratio > 100 {
						log.Printf("RESPONSE_LEAK: zip_bomb_suspected status=%d content_encoding=%s ratio=%.0f", resp.StatusCode, ce, ratio)
						resp.Body = io.NopCloser(bytes.NewReader(compBytes))
						resp.Header.Set("Content-Encoding", ce)
						return nil
					}
				}
				if rerr != nil {
					truncated = true
					log.Printf("RESPONSE_LEAK: truncated=true status=%d content_encoding=%s err=%v", resp.StatusCode, ce, rerr)
				}
				report := scanner.Scan(decBytes)
				if report.HasAny() {
					for _, t := range report.Types() {
						if s.metrics != nil {
							s.metrics.IncResponseLeak(t)
						}
					}
					log.Printf("RESPONSE_LEAK: status=%d content_type=%s types=%v action=%s truncated=%v content_encoding=%s decompressed=true", resp.StatusCode, mediaType, report.Types(), cfg.ResponseInspectionMode, truncated, ce)
					if cfg.ResponseInspectionMode == config.EgressModeBlock {
						switch cfg.ResponseInspectionOnLeak {
						case "block":
							_ = resp.Body.Close()
							resp.StatusCode = http.StatusBadGateway
							resp.Body = io.NopCloser(bytes.NewReader([]byte(`{"error":"response blocked by 7Guard"}`)))
							resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(`{"error":"response blocked by 7Guard"}`)))
							resp.Header.Del("Content-Encoding")
							return nil
						case "strip", "replace":
							log.Printf("RESPONSE_LEAK: skipped_modification_compressed status=%d", resp.StatusCode)
							resp.Body = io.NopCloser(bytes.NewReader(compBytes))
							resp.Header.Set("Content-Encoding", ce)
							return nil
						}
					}
				}
				// detect mode or no leak: pass original compressed body through.
				resp.Body = io.NopCloser(bytes.NewReader(compBytes))
				resp.Header.Set("Content-Encoding", ce)
				return nil
			}
			allowed := contentTypeAllowed(cfg, mediaType)
			// Redirects: pass through unmodified.
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				return nil
			}
			if !allowed {
				return nil
			}
			maxBytes := cfg.ResponseInspectionMaxBodyBytes
			if maxBytes <= 0 {
				maxBytes = 1 << 20
			}
			// Read up to maxBytes+1 to detect truncation without unbounded buffering.
			buf, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
			if err != nil {
				return err
			}
			truncated := len(buf) > int(maxBytes)
			scanBuf := buf
			if truncated {
				scanBuf = buf[:maxBytes]
			}
			report := scanner.Scan(scanBuf)
			if report.HasAny() {
				for _, t := range report.Types() {
					if s.metrics != nil {
						s.metrics.IncResponseLeak(t)
					}
				}
				log.Printf("RESPONSE_LEAK: status=%d content_type=%s types=%v action=%s truncated=%v", resp.StatusCode, mediaType, report.Types(), cfg.ResponseInspectionMode, truncated)
				if cfg.ResponseInspectionMode == config.EgressModeBlock {
					switch cfg.ResponseInspectionOnLeak {
					case "block":
						_ = resp.Body.Close()
						resp.StatusCode = http.StatusBadGateway
						resp.Body = io.NopCloser(bytes.NewReader([]byte(`{"error":"response blocked by 7Guard"}`)))
						resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(`{"error":"response blocked by 7Guard"}`)))
						resp.Header.Del("Content-Encoding")
						return nil
					case "strip", "replace":
						if truncated {
							// Cannot safely strip without the full body; pass through unmodified.
							resp.Body = &closingReader{r: io.MultiReader(bytes.NewReader(buf), resp.Body), c: resp.Body}
							return nil
						}
						token := cfg.ResponseInspectionReplaceToken
						if cfg.ResponseInspectionOnLeak == "strip" {
							token = ""
						}
						// Single-pass replacement using merged spans to avoid
						// overlapping/substring corruption.
						type span struct{ start, end int }
						var spans []span
						for _, f := range report.Findings {
							spans = append(spans, span{start: f.Offset, end: f.Offset + len(f.Matched)})
						}
						// sort by start
						for i := 1; i < len(spans); i++ {
							for j := i; j > 0 && spans[j-1].start > spans[j].start; j-- {
								spans[j-1], spans[j] = spans[j], spans[j-1]
							}
						}
						// merge overlapping
						var merged []span
						for _, sp := range spans {
							if len(merged) > 0 && sp.start <= merged[len(merged)-1].end {
								if sp.end > merged[len(merged)-1].end {
									merged[len(merged)-1].end = sp.end
								}
							} else {
								merged = append(merged, sp)
							}
						}
						var b strings.Builder
						cur := 0
						for _, sp := range merged {
							if sp.start > cur {
								b.WriteString(string(buf[cur:sp.start]))
							}
							b.WriteString(token)
							cur = sp.end
						}
						if cur < len(buf) {
							b.WriteString(string(buf[cur:]))
						}
						newBody := []byte(b.String())
						_ = resp.Body.Close()
						resp.Body = io.NopCloser(bytes.NewReader(newBody))
						resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
						resp.Header.Del("Content-Encoding")
						return nil
					}
				}
			}
			// detect mode or no leak: pass full body through unmodified.
			resp.Body = &closingReader{r: io.MultiReader(bytes.NewReader(buf), resp.Body), c: resp.Body}
			return nil
		}

	}
	rp.Director = func(req *http.Request) {
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host
	}

	return s, nil
}

// closingReader wraps a reader and closes the underlying on Close.
type closingReader struct {
	r io.Reader
	c io.Closer
}

func (cr *closingReader) Read(p []byte) (int, error) { return cr.r.Read(p) }
func (cr *closingReader) Close() error {
	if cr.c != nil {
		return cr.c.Close()
	}
	return nil
}
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

// contentTypeAllowed reports whether mediaType should be scanned given cfg.
func contentTypeAllowed(cfg *config.Config, mediaType string) bool {
	allowed := false
	if len(cfg.ResponseInspectionContentTypes) == 0 {
		if strings.HasPrefix(mediaType, "text/") {
			allowed = true
		}
		if mediaType == "application/json" || mediaType == "application/xml" || mediaType == "application/javascript" {
			allowed = true
		}
	} else {
		for _, p := range cfg.ResponseInspectionContentTypes {
			if p == "" {
				continue
			}
			if strings.HasSuffix(p, "/*") {
				prefix := strings.TrimSuffix(p, "/*")
				if strings.HasPrefix(mediaType, prefix+"/") {
					allowed = true
					break
				}
			} else if mediaType == p {
				allowed = true
				break
			}
		}
	}
	return allowed
}
