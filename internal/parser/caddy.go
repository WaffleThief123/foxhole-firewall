package parser

import (
	"encoding/json"
	"fmt"
	"time"
)

// Caddy v2 typically logs in JSON with fields like:
// {"request":{"remote_ip":"127.0.0.1","method":"GET","uri":"/"},"status":200,"ts":"2020-10-10T13:55:36.123Z"}

type caddyLog struct {
	Request struct {
		RemoteIP string `json:"remote_ip"`
		Method   string `json:"method"`
		URI      string `json:"uri"`
	} `json:"request"`
	Status int       `json:"status"`
	TS     time.Time `json:"ts"`
}

type caddyParser struct{}

func newCaddyParser() *caddyParser {
	return &caddyParser{}
}

func (p *caddyParser) Parse(line string) (*Event, error) {
	var cl caddyLog
	if err := json.Unmarshal([]byte(line), &cl); err != nil {
		return nil, fmt.Errorf("caddy parser: invalid json: %w", err)
	}

	ts := cl.TS
	if ts.IsZero() {
		ts = time.Now()
	}

	return &Event{
		RemoteAddr: cl.Request.RemoteIP,
		Method:     cl.Request.Method,
		Path:       cl.Request.URI,
		Status:     cl.Status,
		Timestamp:  ts,
		Raw:        line,
	}, nil
}
