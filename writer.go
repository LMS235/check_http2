package main

import (
	"bytes"
	"fmt"
)

// CapWriter counts everything written to it and looks for Needle in the stream,
// but keeps no more than Cap bytes in memory. With NoDiscard set, a write that
// would exceed Cap fails instead of being discarded.
type CapWriter struct {
	Cap       uint64
	NoDiscard bool
	Needle    []byte

	size  uint64
	carry []byte
	found bool
}

func (w *CapWriter) Write(p []byte) (int, error) {
	size := w.size + uint64(len(p))
	if size > w.Cap && w.NoDiscard {
		return 0, fmt.Errorf("could not write body buffer: buffer is full")
	}

	// Always report consuming the whole slice so callers like io.Copy don't treat this as a short write.
	w.size = size

	w.scan(p)

	return len(p), nil
}

// scan searches the stream for Needle, keeping the tail of each chunk so a
// Needle split across two writes is still found.
func (w *CapWriter) scan(p []byte) {
	if w.found || len(w.Needle) == 0 {
		return
	}

	buf := p
	if len(w.carry) > 0 {
		buf = make([]byte, 0, len(w.carry)+len(p))
		buf = append(buf, w.carry...)
		buf = append(buf, p...)
	}

	if bytes.Contains(buf, w.Needle) {
		w.found = true
		w.carry = nil
		return
	}

	keep := min(len(w.Needle)-1, len(buf))
	w.carry = append(w.carry[:0], buf[len(buf)-keep:]...)
}

func (w *CapWriter) Size() uint64 {
	return w.size
}

// Found reports whether Needle occurred anywhere in the stream, including
// beyond Cap.
func (w *CapWriter) Found() bool {
	return len(w.Needle) > 0 && w.found
}
