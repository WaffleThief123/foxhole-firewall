package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Apache common/combined log format example:
// 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
// 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com/start.html" "Mozilla/4.08"

var (
	apacheRe      = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^"]*) HTTP/[0-9.]+" (\d{3}) \S+.*$`)
	apacheTimeFmt = "02/Jan/2006:15:04:05 -0700"
)

type apacheCommonParser struct{}

func newApacheCommonParser() *apacheCommonParser {
	return &apacheCommonParser{}
}

func (p *apacheCommonParser) Parse(line string) (*Event, error) {
	m := apacheRe.FindStringSubmatch(line)
	if len(m) < 6 {
		return nil, fmt.Errorf("apache parser: line does not match expected format")
	}

	ip := m[1]
	tsRaw := m[2]
	method := m[3]
	path := m[4]
	statusStr := m[5]

	ts, err := time.Parse(apacheTimeFmt, tsRaw)
	if err != nil {
		return nil, fmt.Errorf("apache parser: parse time: %w", err)
	}

	status, err := strconv.Atoi(statusStr)
	if err != nil {
		return nil, fmt.Errorf("apache parser: parse status: %w", err)
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
