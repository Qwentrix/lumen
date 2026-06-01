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

//go:build !darwin && !linux

// Package compliance stubs for non-darwin/linux platforms (e.g. Windows).
// Windows compliance probes are implemented in LU-5.
package compliance

import "context"

func collectDiskEncryption(_ context.Context, meta map[string]interface{}) bool {
	meta["disk_encryption_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return false
}

func collectFirewall(_ context.Context, meta map[string]interface{}) bool {
	meta["firewall_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return false
}

func collectScreenLock(_ context.Context, meta map[string]interface{}) screenLockResult {
	meta["screen_lock_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return screenLockResult{}
}
