package parser

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Traefik access logs in JSON (common pattern):
// {"ClientAddr":"127.0.0.1:54321","ClientHost":"127.0.0.1","DownstreamStatus":200,"RequestMethod":"GET","RequestPath":"/","StartUTC":"2020-10-10T13:55:36.123Z"}

type traefikLog struct {
	ClientAddr       string `json:"ClientAddr"`
	ClientHost       string `json:"ClientHost"`
	DownstreamStatus int    `json:"DownstreamStatus"`
	RequestMethod    string `json:"RequestMethod"`
	RequestPath      string `json:"RequestPath"`
	StartUTC         string `json:"StartUTC"`
}

type traefikParser struct{}

func newTraefikParser() *traefikParser {
	return &traefikParser{}
}

func (p *traefikParser) Parse(line string) (*Event, error) {
	var tl traefikLog
	if err := json.Unmarshal([]byte(line), &tl); err != nil {
		return nil, fmt.Errorf("traefik parser: invalid json: %w", err)
	}

	ts, err := time.Parse(time.RFC3339Nano, tl.StartUTC)
	if err != nil {
		ts = time.Now()
	}

	ip := tl.ClientHost
	if ip == "" && tl.ClientAddr != "" {
		// Fallback: ClientAddr is "ip:port" - use net.SplitHostPort for proper IPv6 handling.
		host, _, err := net.SplitHostPort(tl.ClientAddr)
		if err == nil {
			ip = host
		} else {
			// If SplitHostPort fails, assume it's just an IP without port.
			ip = tl.ClientAddr
		}
	}

	return &Event{
		RemoteAddr: ip,
		Method:     tl.RequestMethod,
		Path:       tl.RequestPath,
		Status:     tl.DownstreamStatus,
		Timestamp:  ts,
		Raw:        line,
	}, nil
}
