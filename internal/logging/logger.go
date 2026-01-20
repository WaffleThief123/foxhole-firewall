package logging

import (
	"log"
	"os"
)

// Logger is a minimal interface-compatible logger that can be swapped later.
type Logger struct {
	l *log.Logger
}

// NewLogger creates a new stdout logger with a simple prefix.
func NewLogger() *Logger {
	return &Logger{
		l: log.New(os.Stdout, "[foxhole-fw] ", log.LstdFlags),
	}
}

func (l *Logger) Info(msg string) {
	l.l.Println("INFO:", msg)
}

func (l *Logger) Infof(format string, args ...any) {
	l.l.Printf("INFO: "+format+"\n", args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.l.Printf("ERROR: "+format+"\n", args...)
}
