package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var (
	// Example combined log format:
	// 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "UserAgent"
	nginxCombinedRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^"]*) HTTP/[0-9.]+" (\d{3}) \S+ "([^"]*)" "([^"]*)"$`)
	timeLayout      = "02/Jan/2006:15:04:05 -0700"
)

// ErrUnknownParser is returned when an unsupported parser name is requested.
var ErrUnknownParser = fmt.Errorf("unknown parser")

type nginxCombinedParser struct{}

func newNginxCombinedParser() *nginxCombinedParser {
	return &nginxCombinedParser{}
}

func (p *nginxCombinedParser) Parse(line string) (*Event, error) {
	matches := nginxCombinedRe.FindStringSubmatch(line)
	if len(matches) < 6 {
		return nil, fmt.Errorf("nginx parser: line does not match expected format")
	}

	ip := matches[1]
	tsRaw := matches[2]
	method := matches[3]
	path := matches[4]
	statusStr := matches[5]

	ts, err := time.Parse(timeLayout, tsRaw)
	if err != nil {
		return nil, fmt.Errorf("nginx parser: parse time: %w", err)
	}

	status, err := strconv.Atoi(statusStr)
	if err != nil {
		return nil, fmt.Errorf("nginx parser: parse status: %w", err)
	}

	return &Event{
		RemoteAddr: ip,
		Method:     method,
		Path:       path,
		Status:     status,
		Timestamp:  ts,
		Raw:        line,
	}, nil
}
