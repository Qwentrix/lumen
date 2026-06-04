//go:build ignore

// DEV-ONLY: excluded from all builds. Prints ai_governance + security_posture +
// privacy ScannerFindings to stdout for ENT-107 verification.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/manifest"
	"github.com/Qwentrix/lumen/internal/probes/ai_governance"
	"github.com/Qwentrix/lumen/internal/probes/privacy"
	"github.com/Qwentrix/lumen/internal/probes/security_posture"
)

func main() {
	withPrivacy := false
	for _, arg := range os.Args[1:] {
		if arg == "--include-privacy" {
			withPrivacy = true
		}
	}

	manifest.Default = manifest.New("debug")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	aigr, err := ai_governance.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ai_governance error: %v\n", err)
		os.Exit(1)
	}

	spr, err := security_posture.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "security_posture error: %v\n", err)
		os.Exit(1)
	}

	sf := &lstypes.ScannerFindings{}
	if aigr.ScannerFields.AIGovernance != nil {
		sf.AIGovernance = *aigr.ScannerFields.AIGovernance
	}
	if spr.ScannerFields.SecurityPosture != nil {
		sf.SecurityPosture = *spr.ScannerFields.SecurityPosture
	}

	var privJSON interface{}
	if withPrivacy {
		prr, err := privacy.RunWithPrivacy(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "privacy error: %v\n", err)
			os.Exit(1)
		}
		privJSON = prr.ScannerFields.Privacy
	} else {
		prr, _ := privacy.Run(ctx)
		privJSON = prr.ScannerFields.Privacy
	}

	type output struct {
		AIGovernance    lstypes.AIGovernanceFindings    `json:"ai_governance"`
		SecurityPosture lstypes.SecurityPostureFindings `json:"security_posture"`
		Privacy         interface{}                     `json:"privacy"`
	}
	o := output{
		AIGovernance:    sf.AIGovernance,
		SecurityPosture: sf.SecurityPosture,
		Privacy:         privJSON,
	}

	out, _ := json.MarshalIndent(o, "", "  ")
	fmt.Println(string(out))

	fmt.Println("\n--- ai_governance metadata ---")
	for k, v := range aigr.Metadata {
		fmt.Printf("  %s: %v\n", k, v)
	}
	fmt.Println("\n--- security_posture metadata ---")
	for k, v := range spr.Metadata {
		fmt.Printf("  %s: %v\n", k, v)
	}
}
