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

package rules

import (
	"testing"
)

func TestLoadEmbedded(t *testing.T) {
	ruleStore, overlayStore, cleanup, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	defer cleanup()

	if ruleStore.Count() == 0 {
		t.Error("embedded rule store is empty — expected VULN_* and COMP_* rules")
	}
	if overlayStore.Count() == 0 {
		t.Error("embedded overlay store is empty — expected 10 industry overlays")
	}

	t.Logf("Loaded %d rules, %d overlays", ruleStore.Count(), overlayStore.Count())

	// Verify a known rule is present.
	rule := ruleStore.ByID("COMP_NO_ENCRYPTION_AT_REST")
	if rule == nil {
		t.Error("expected rule COMP_NO_ENCRYPTION_AT_REST to be present")
	} else {
		if rule.Domain != "compliance" {
			t.Errorf("COMP_NO_ENCRYPTION_AT_REST domain: got %q, want compliance", rule.Domain)
		}
		if rule.DefaultWeight <= 0 {
			t.Errorf("COMP_NO_ENCRYPTION_AT_REST default_weight: got %f, want > 0", rule.DefaultWeight)
		}
	}

	// Verify an overlay is present.
	overlay := overlayStore.ByID("healthcare")
	if overlay == nil {
		t.Error("expected overlay 'healthcare' to be present")
	}

	// Verify all expected overlays are loaded.
	expectedOverlays := []string{
		"healthcare", "financial", "technology", "government",
		"education", "energy", "legal", "manufacturing", "retail", "it_services",
	}
	for _, id := range expectedOverlays {
		if o := overlayStore.ByID(id); o == nil {
			t.Errorf("overlay %q not found in embedded store", id)
		}
	}
}

func TestMetaJSON_NonEmpty(t *testing.T) {
	if len(MetaJSON) == 0 {
		t.Error("MetaJSON is empty — expected content-snapshot.meta.json to be embedded")
	}
	// Basic sanity: should contain the source_sha key.
	if string(MetaJSON[:10]) != "{\n  \"source" {
		// Just check it's valid JSON-ish.
		if MetaJSON[0] != '{' {
			t.Error("MetaJSON does not start with '{' — may not be valid JSON")
		}
	}
}
