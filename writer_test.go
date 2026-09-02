package main

import (
	"strings"
	"testing"
)

func TestCapWriterWriteWithinCap(t *testing.T) {
	w := &CapWriter{Cap: 8}

	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 5 {
		t.Fatalf("Write() n = %d, want 5", n)
	}
	if got := w.Size(); got != 5 {
		t.Fatalf("Size() = %d, want 5", got)
	}
}

// over the cap the write is still reported as consumed, so io.Copy drains the
// body instead of failing on a short write
func TestCapWriterWriteOverCapDiscard(t *testing.T) {
	w := &CapWriter{Cap: 4}

	n, err := w.Write([]byte("abcdef"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 6 {
		t.Fatalf("Write() n = %d, want 6", n)
	}
	if got := w.Size(); got != 6 {
		t.Fatalf("Size() = %d, want 6", got)
	}
}

func TestCapWriterWriteOverCapAcrossWritesDiscard(t *testing.T) {
	w := &CapWriter{Cap: 5}
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}

	n, err := w.Write([]byte("defg"))
	if err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	if n != 4 {
		t.Fatalf("second Write() n = %d, want 4", n)
	}
	if got := w.Size(); got != 7 {
		t.Fatalf("Size() = %d, want 7", got)
	}
}

func TestCapWriterWriteOverCapNoDiscard(t *testing.T) {
	w := &CapWriter{Cap: 4, NoDiscard: true}

	n, err := w.Write([]byte("abcdef"))
	if err == nil {
		t.Fatalf("Write() error = nil, want non-nil")
	}
	if n != 0 {
		t.Fatalf("Write() n = %d, want 0", n)
	}
	if got := w.Size(); got != 0 {
		t.Fatalf("Size() = %d, want 0", got)
	}
}

func TestCapWriterFound(t *testing.T) {
	tests := []struct {
		name   string
		cap    uint64
		needle string
		writes []string
		want   bool
	}{
		{"no needle configured", 8, "", []string{"abc"}, false},
		{"within cap", 8, "bc", []string{"abcd"}, true},
		{"absent", 8, "xy", []string{"abcd"}, false},
		// the point of scanning the stream: the needle sits past the cap
		{"beyond cap", 4, "needle", []string{strings.Repeat("a", 100) + "needle"}, true},
		{"beyond cap in a later write", 4, "needle", []string{"aaaa", "bbbb", "needle"}, true},
		// and it may straddle two writes
		{"split across writes", 4, "needle", []string{"aaaanee", "dleaaaa"}, true},
		{"split across three writes", 4, "needle", []string{"aaaane", "ed", "leaaa"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &CapWriter{Cap: tt.cap, Needle: []byte(tt.needle)}
			for _, s := range tt.writes {
				if _, err := w.Write([]byte(s)); err != nil {
					t.Fatalf("Write(%q) error = %v", s, err)
				}
			}
			if got := w.Found(); got != tt.want {
				t.Fatalf("Found() = %v, want %v", got, tt.want)
			}
		})
	}
}
