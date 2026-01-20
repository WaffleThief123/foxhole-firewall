package parser

import "time"

// Event represents a normalized HTTP request extracted from a log line.
type Event struct {
	RemoteAddr string
	Method     string
	Path       string
	Status     int
	Timestamp  time.Time

	Raw string
}

// Parser defines the interface implemented by log parsers.
type Parser interface {
	Parse(line string) (*Event, error)
}

// New returns a parser implementation by name.
func New(name string) (Parser, error) {
	switch name {
	case "nginx_combined", "nginx":
		return newNginxCombinedParser(), nil
	case "apache_common", "apache":
		return newApacheCommonParser(), nil
	case "caddy":
		return newCaddyParser(), nil
	case "traefik":
		return newTraefikParser(), nil
	default:
		return nil, ErrUnknownParser
	}
}
