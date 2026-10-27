package proxy

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func copyRulesDir(t *testing.T, dst string) {
	t.Helper()
	src := "../../rules"
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPhase9ReloadRulesSuccess(t *testing.T) {
	dir := t.TempDir()
	copyRulesDir(t, dir)
	cfg := config.Default()
	cfg.RulesDir = dir
	cfg.Upstream = "http://localhost:9090"
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := srv.ReloadRules()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if n == 0 {
		t.Fatal("expected >0 rules after reload")
	}
}

func TestPhase9ReloadRulesKeepsOldOnFailure(t *testing.T) {
	dir := t.TempDir()
	copyRulesDir(t, dir)
	cfg := config.Default()
	cfg.RulesDir = dir
	cfg.Upstream = "http://localhost:9090"
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	oldCount := len(srv.rules)
	// corrupt a rule file
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte(":::invalid yaml:::"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = srv.ReloadRules()
	if err == nil {
		t.Fatal("expected reload error on malformed rules")
	}
	if len(srv.rules) != oldCount {
		t.Errorf("rules changed on failed reload: %d -> %d", oldCount, len(srv.rules))
	}
	_ = os.Remove(bad)
}

func TestPhase9HotReloadWatcher(t *testing.T) {
	dir := t.TempDir()
	copyRulesDir(t, dir)
	cfg := config.Default()
	cfg.RulesDir = dir
	cfg.Upstream = "http://localhost:9090"
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	oldCount := len(srv.rules)
	stop, err := srv.StartWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	// add a new rule file to trigger Create event -> reload
	newRule := "- id: hotreload-test-rule\n  category: test\n  severity: low\n  pattern: \"hotreloadcanary\"\n  locations: [query]\n  description: \"hot reload test\"\n"
	if err := os.WriteFile(filepath.Join(dir, "hotreload.yaml"), []byte(newRule), 0644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.rules) > oldCount {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(srv.rules) <= oldCount {
		t.Errorf("rules did not reload: %d -> %d", oldCount, len(srv.rules))
	}
}

func TestPhase9ReloadConcurrency(t *testing.T) {
	dir := t.TempDir()
	copyRulesDir(t, dir)
	cfg := config.Default()
	cfg.RulesDir = dir
	cfg.Upstream = "http://localhost:9090"
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				srv.ReloadRules()
			}
		}
	}()
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/?q=1+UNION+SELECT+1", nil)
		rr := httptest.NewRecorder()
		srv.handleRequest(rr, req)
	}
	close(done)
	wg.Wait()
}

func TestPhase9WatcherStop(t *testing.T) {
	dir := t.TempDir()
	copyRulesDir(t, dir)
	cfg := config.Default()
	cfg.RulesDir = dir
	cfg.Upstream = "http://localhost:9090"
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := srv.StartWatcher()
	if err != nil {
		t.Fatal(err)
	}
	oldCount := len(srv.rules)
	stop()
	// after stop, modifying a file should not panic / should be safe
	files, _ := os.ReadDir(dir)
	if len(files) == 0 {
		t.Fatal("no files")
	}
	target := filepath.Join(dir, files[0].Name())
	data, _ := os.ReadFile(target)
	_ = os.WriteFile(target, data, 0644)
	time.Sleep(200 * time.Millisecond)
	if len(srv.rules) != oldCount {
		t.Errorf("watcher not stopped: rules changed %d -> %d", oldCount, len(srv.rules))
	}
}
