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

//go:build !darwin && !linux && !windows

// Package security_posture stubs for non-darwin/linux/windows platforms.
// Windows security posture probes are implemented in collect_windows.go (ENT-108).
package security_posture

import "context"

func collectSSHKeys(_ context.Context, meta map[string]interface{}) (total, weak int) {
	meta["ssh_keys_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return 0, 0
}

func collectPasswordManager(_ context.Context, meta map[string]interface{}) bool {
	meta["pm_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return false
}

func collectListeningPorts(_ context.Context, meta map[string]interface{}) int {
	meta["listening_ports_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return 0
}
