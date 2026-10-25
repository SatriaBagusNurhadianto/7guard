package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
	"github.com/SatriaBagusNurhadianto/7guard/internal/detector"
	"github.com/SatriaBagusNurhadianto/7guard/internal/rules"
)

// Server is the 7Guard reverse proxy.
type Server struct {
	cfg   *config.Config
	rules []rules.Rule
	det   *detector.Detector
	proxy *httputil.ReverseProxy
}

// New creates a new 7Guard server.
func New(cfg *config.Config) (*Server, error) {
	rs, err := rules.LoadRules(cfg.RulesDir)
	if err != nil {
		// Rules dir may not exist yet; start with empty rules
		log.Printf("warning: could not load rules: %v", err)
		rs = []rules.Rule{}
	}

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL: %w", err)
	}

	rp := httputil.NewSingleHostReverseProxy(upstream)

	s := &Server{
		cfg:   cfg,
		rules: rs,
		det:   detector.New(rs),
		proxy: rp,
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

	log.Printf("7Guard listening on %s (profile=%s, mode=%s)", s.cfg.ListenAddr, s.cfg.Profile, s.cfg.Mode)
	return srv.ListenAndServe()
}

// handleRequest processes incoming requests through the detection pipeline.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// 1. Check body size
	if r.ContentLength > s.cfg.MaxBodySize {
		http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
		return
	}

	// 2. Normalize + Detect
	matches := s.det.Detect(r)

	// 3. Score
	score := 0
	for _, m := range matches {
		score += severityScore(m.Rule.Severity)
	}

	// 4. Log
	if len(matches) > 0 {
		logMatch(r, matches, score, s.cfg.Mode)
	}

	// 5. Decision
	threshold := 5 // configurable later
	if score >= threshold {
		if s.cfg.Mode == config.ModeBlock {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "blocked by 7Guard",
				"score":   score,
				"matches": len(matches),
			})
			return
		}
		// detect mode: log and pass through
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
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Mode      string   `json:"mode"`
	Score     int      `json:"score"`
	Matches   int      `json:"matches"`
	Rules     []string `json:"rules"`
}

func logMatch(r *http.Request, matches []detector.Match, score int, mode string) {
	var ruleIDs []string
	for _, m := range matches {
		ruleIDs = append(ruleIDs, m.Rule.ID)
	}
	entry := logEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Method:    r.Method,
		Path:      r.URL.Path,
		Mode:      mode,
		Score:     score,
		Matches:   len(matches),
		Rules:     ruleIDs,
	}
	b, _ := json.Marshal(entry)
	log.Printf("DETECT: %s", string(b))
}
