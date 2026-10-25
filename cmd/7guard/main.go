package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
	"github.com/SatriaBagusNurhadianto/7guard/internal/proxy"
)

func main() {
	cfg := config.Default()

	flag.StringVar(&cfg.Profile, "profile", "lite", "deployment profile (lite|full|advanced|max)")
	flag.StringVar(&cfg.Mode, "mode", "detect", "operating mode (detect|block)")
	flag.BoolVar(&cfg.ConfirmBlock, "confirm-block", false, "required to enable block mode")
	flag.StringVar(&cfg.ListenAddr, "listen", ":8080", "listen address")
	flag.StringVar(&cfg.Upstream, "upstream", "http://localhost:9090", "upstream backend URL")
	flag.Int64Var(&cfg.MaxBodySize, "max-body-size", 1048576, "max request body size in bytes")
	flag.StringVar(&cfg.RulesDir, "rules-dir", "./rules", "directory containing YAML rule files")
	flag.IntVar(&cfg.RateLimit, "rate-limit", 0, "rate limit in requests per minute (0 = profile default)")
	flag.StringVar(&cfg.TLSCertFile, "tls-cert", "", "TLS certificate file (enables HTTPS)")
	flag.StringVar(&cfg.TLSKeyFile, "tls-key", "", "TLS key file (enables HTTPS)")
	flag.StringVar(&cfg.JWTSecret, "jwt-secret", "", "JWT signing secret (enables JWT validation)")

	flag.Parse()

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	log.Printf("7Guard starting: profile=%s mode=%s listen=%s upstream=%s", cfg.Profile, cfg.Mode, cfg.ListenAddr, cfg.Upstream)

	srv, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy init error: %v\n", err)
		os.Exit(1)
	}

	if err := srv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
