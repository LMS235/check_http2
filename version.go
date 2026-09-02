package main

// defaultVersion is the version reported when the binary is built without the
// ldflags the Makefile passes, as a plain "go build" does. tagpr keeps it in
// sync with the Makefile on release (see .tagpr).
const defaultVersion = "0.0.30"
