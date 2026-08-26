package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type entry struct {
	TS     time.Time `json:"ts"`
	PID    int       `json:"pid"`
	Cmd    string    `json:"cmd"`
	Argv   []string  `json:"argv,omitempty"`
	Domain string    `json:"domain,omitempty"`
	QType  string    `json:"qtype,omitempty"`
	Rule   string    `json:"rule,omitempty"`
	Mode   string    `json:"mode"` // passthrough|spoof|rewrite|reject
	Real   string    `json:"real,omitempty"`
	Exit   *int      `json:"exit,omitempty"`
}

func logPath(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	p := strings.TrimSpace(cfg.LogFile)
	if p == "" {
		return ""
	}
	return expandHome(p)
}

func appendLog(path string, e entry) {
	if path == "" {
		return
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}
