//go:build ignore

// DEV-ONLY: excluded from all builds and tests. Local debugging helper for probe output. Do NOT remove the //go:build ignore tag.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/manifest"
	"github.com/Qwentrix/lumen/internal/probes/compliance"
	"github.com/Qwentrix/lumen/internal/probes/vulnerabilities"
)

func main() {
	manifest.Default = manifest.New("debug")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	vr, err := vulnerabilities.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vuln error: %v\n", err)
		os.Exit(1)
	}
	cr, err := compliance.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compliance error: %v\n", err)
		os.Exit(1)
	}

	sf := &lstypes.ScannerFindings{}
	if vr.ScannerFields.Vulnerabilities != nil {
		sf.Vulnerabilities = *vr.ScannerFields.Vulnerabilities
	}
	if cr.ScannerFields.Compliance != nil {
		sf.Compliance = *cr.ScannerFields.Compliance
	}

	out, _ := json.MarshalIndent(sf, "", "  ")
	fmt.Println(string(out))

	fmt.Println("\n--- vuln metadata ---")
	for k, v := range vr.Metadata {
		fmt.Printf("  %s: %v\n", k, v)
	}
	fmt.Println("\n--- compliance metadata ---")
	for k, v := range cr.Metadata {
		fmt.Printf("  %s: %v\n", k, v)
	}
}
