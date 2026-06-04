// Copyright 2026 Qwentrix Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hybrid

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// PreviewAndConfirm pretty-prints the exact JSON that will be uploaded to out
// and prompts the user for explicit confirmation on in. Returns nil if the user
// confirms with "y" or "yes" (case-insensitive). Returns ErrAborted for any
// other input (including empty, "n", "no", or Ctrl-D).
//
// Acceptance criterion: "preview shows exact payload, no surprises".
// The bytes printed are json.MarshalIndent of the SIGNED payload — exactly what
// will be sent to the server, including the computed signature field.
//
// gatewayBaseURL is the REAL destination URL that Upload() will POST to (e.g.
// "https://lumen.micelium.com"). It is printed in the confirmation prompt so the
// user sees exactly where their data is going. The caller must resolve the URL
// (via --server flag or LUMEN_SERVER_URL env) before calling PreviewAndConfirm;
// pass DefaultGatewayBaseURL when no override is in effect.
//
// It is the caller's responsibility to call Sign before calling PreviewAndConfirm
// so that the printed payload is the final signed form.
func PreviewAndConfirm(p *UploadPayload, out io.Writer, in io.Reader, gatewayBaseURL string) error {
	if gatewayBaseURL == "" {
		gatewayBaseURL = DefaultGatewayBaseURL
	}
	ingestURL := gatewayBaseURL + ingestPath

	pretty, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("hybrid: marshal preview: %w", err)
	}

	fmt.Fprintf(out, "\n--- Hybrid Upload Payload (EXACT JSON to be sent) ---\n")
	fmt.Fprintf(out, "%s\n", string(pretty))
	fmt.Fprintf(out, "--- End of payload ---\n\n")
	fmt.Fprintf(out, "This payload will be sent to %s.\n", ingestURL)
	fmt.Fprintf(out, "Review the payload above. No file content, no PII, no hostnames are included.\n")
	fmt.Fprintf(out, "\nUpload this payload? [y/N]: ")

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return ErrAborted
	}
	answer := strings.TrimSpace(scanner.Text())
	if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
		return nil
	}
	return ErrAborted
}

// ErrAborted is returned when the user declines the upload confirmation.
var ErrAborted = fmt.Errorf("hybrid: upload aborted by user")
