// Package main is the entry point for the Lumen scanner CLI.
// Apache 2.0 — see LICENSE.
package main

import (
	"fmt"
	"os"
)

// Version, Commit, and BuiltAt are injected at build time via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	BuiltAt = "unknown"
)

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
