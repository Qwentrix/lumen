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

package nvd

import "strings"

// normalisedCPE maps a (vendor, product) input to the canonical form used in
// the embedded CVE index. This bridges the gap between OS-level package names
// (e.g. "OpenSSL 3.0.11" from system_profiler) and CPE 2.3 identifiers.
type normalisedCPE struct {
	vendor  string
	product string
}

// cpeTable maps lowercased input (vendor:product) to canonical CPE values.
// Extend this table as new packages are added to the curated index.
var cpeTable = map[string]normalisedCPE{
	// OpenSSL — various capitalisation / package names
	"openssl:openssl": {vendor: "openssl", product: "openssl"},
	"openssl:libssl":  {vendor: "openssl", product: "openssl"},
	"openssl:libssl3": {vendor: "openssl", product: "openssl"},
	":openssl":        {vendor: "openssl", product: "openssl"},
	":libssl3":        {vendor: "openssl", product: "openssl"},
	// OpenSSH
	"openbsd:openssh": {vendor: "openbsd", product: "openssh"},
	":openssh":        {vendor: "openbsd", product: "openssh"},
	":openssh-client": {vendor: "openbsd", product: "openssh"},
	":openssh-server": {vendor: "openbsd", product: "openssh"},
	// curl
	"haxx:curl": {vendor: "haxx", product: "curl"},
	":curl":     {vendor: "haxx", product: "curl"},
	":libcurl4": {vendor: "haxx", product: "curl"},
	// sudo
	"sudo_project:sudo": {vendor: "sudo_project", product: "sudo"},
	":sudo":             {vendor: "sudo_project", product: "sudo"},
	// log4j — typically found in JVM app bundles
	"apache:log4j": {vendor: "apache", product: "log4j"},
	":log4j":       {vendor: "apache", product: "log4j"},
	":log4j-core":  {vendor: "apache", product: "log4j"},
	// Python
	"python:python": {vendor: "python", product: "python"},
	":python3":      {vendor: "python", product: "python"},
	":python3.9":    {vendor: "python", product: "python"},
	":python3.10":   {vendor: "python", product: "python"},
	":python3.11":   {vendor: "python", product: "python"},
	":python3.12":   {vendor: "python", product: "python"},
	// Node.js
	"nodejs:node.js": {vendor: "nodejs", product: "node.js"},
	":nodejs":        {vendor: "nodejs", product: "node.js"},
	":node.js":       {vendor: "nodejs", product: "node.js"},
	// SQLite
	"sqlite:sqlite": {vendor: "sqlite", product: "sqlite"},
	":sqlite3":      {vendor: "sqlite", product: "sqlite"},
	":libsqlite3-0": {vendor: "sqlite", product: "sqlite"},
	// glibc
	"gnu:glibc": {vendor: "gnu", product: "glibc"},
	":libc6":    {vendor: "gnu", product: "glibc"},
	":glibc":    {vendor: "gnu", product: "glibc"},
	// Chrome
	"google:chrome":         {vendor: "google", product: "chrome"},
	":google-chrome-stable": {vendor: "google", product: "chrome"},
	":google-chrome":        {vendor: "google", product: "chrome"},
	// Firefox
	"mozilla:firefox": {vendor: "mozilla", product: "firefox"},
	":firefox":        {vendor: "mozilla", product: "firefox"},
	":firefox-esr":    {vendor: "mozilla", product: "firefox"},
	// zlib
	"zlib:zlib": {vendor: "zlib", product: "zlib"},
	":zlib1g":   {vendor: "zlib", product: "zlib"},
	// libpng
	"libpng:libpng": {vendor: "libpng", product: "libpng"},
	":libpng16-16":  {vendor: "libpng", product: "libpng"},
	// expat
	"libexpat_project:libexpat": {vendor: "libexpat_project", product: "libexpat"},
	":libexpat1":                {vendor: "libexpat_project", product: "libexpat"},
	":expat":                    {vendor: "libexpat_project", product: "libexpat"},
	// Nginx
	"nginx:nginx": {vendor: "nginx", product: "nginx"},
	":nginx":      {vendor: "nginx", product: "nginx"},
	// Apache httpd
	"apache:http_server": {vendor: "apache", product: "http_server"},
	":apache2":           {vendor: "apache", product: "http_server"},
	":httpd":             {vendor: "apache", product: "http_server"},
	// Git
	"git-scm:git": {vendor: "git-scm", product: "git"},
	":git":        {vendor: "git-scm", product: "git"},
	// wget
	"gnu:wget": {vendor: "gnu", product: "wget"},
	":wget":    {vendor: "gnu", product: "wget"},
	// Perl
	"perl:perl": {vendor: "perl", product: "perl"},
	":perl":     {vendor: "perl", product: "perl"},
	// bash
	"gnu:bash": {vendor: "gnu", product: "bash"},
	":bash":    {vendor: "gnu", product: "bash"},
	// macOS (version reported by sw_vers)
	"apple:macos": {vendor: "apple", product: "macos"},
	":macos":      {vendor: "apple", product: "macos"},
	// Linux kernel
	"linux:linux_kernel":   {vendor: "linux", product: "linux_kernel"},
	":linux-image-generic": {vendor: "linux", product: "linux_kernel"},
	// vim
	"vim:vim":     {vendor: "vim", product: "vim"},
	":vim":        {vendor: "vim", product: "vim"},
	":vim-common": {vendor: "vim", product: "vim"},
	// tar
	"gnu:tar": {vendor: "gnu", product: "tar"},
	":tar":    {vendor: "gnu", product: "tar"},
	// PostgreSQL
	"postgresql:postgresql": {vendor: "postgresql", product: "postgresql"},
	":postgresql":           {vendor: "postgresql", product: "postgresql"},
	":postgres":             {vendor: "postgresql", product: "postgresql"},
	":postgresql-14":        {vendor: "postgresql", product: "postgresql"},
	":postgresql-15":        {vendor: "postgresql", product: "postgresql"},
	":postgresql-16":        {vendor: "postgresql", product: "postgresql"},
	":postgresql-client":    {vendor: "postgresql", product: "postgresql"},
	":postgresql-server":    {vendor: "postgresql", product: "postgresql"},
	// OpenJDK (Java SE) — NVD tags OpenJDK CVEs as oracle:openjdk; cross-distro
	// version schemes vary, so version matching here is approximate.
	"oracle:openjdk":  {vendor: "oracle", product: "openjdk"},
	":openjdk":        {vendor: "oracle", product: "openjdk"},
	":openjdk-21-jdk": {vendor: "oracle", product: "openjdk"},
	":openjdk-21-jre": {vendor: "oracle", product: "openjdk"},
	":openjdk-17-jdk": {vendor: "oracle", product: "openjdk"},
	":openjdk-17-jre": {vendor: "oracle", product: "openjdk"},
	":openjdk-11-jdk": {vendor: "oracle", product: "openjdk"},
	":openjdk-11-jre": {vendor: "oracle", product: "openjdk"},
	":default-jdk":    {vendor: "oracle", product: "openjdk"},
	":temurin":        {vendor: "oracle", product: "openjdk"},
	// Docker — engine (Linux) and Docker Desktop (macOS) are distinct CPEs.
	"docker:docker":   {vendor: "docker", product: "docker"},
	":docker":         {vendor: "docker", product: "docker"},
	":docker-ce":      {vendor: "docker", product: "docker"},
	":docker.io":      {vendor: "docker", product: "docker"},
	":docker-engine":  {vendor: "docker", product: "docker"},
	"docker:desktop":  {vendor: "docker", product: "desktop"},
	":docker-desktop": {vendor: "docker", product: "desktop"},
	// systemd
	"systemd_project:systemd": {vendor: "systemd_project", product: "systemd"},
	":systemd":                {vendor: "systemd_project", product: "systemd"},
	":libsystemd0":            {vendor: "systemd_project", product: "systemd"},
	":systemd-libs":           {vendor: "systemd_project", product: "systemd"},
	// OpenLDAP
	"openldap:openldap": {vendor: "openldap", product: "openldap"},
	":openldap":         {vendor: "openldap", product: "openldap"},
	":slapd":            {vendor: "openldap", product: "openldap"},
	":libldap-2.5-0":    {vendor: "openldap", product: "openldap"},
	":libldap-common":   {vendor: "openldap", product: "openldap"},
	":openldap-servers": {vendor: "openldap", product: "openldap"},
	// Redis
	"redis:redis":   {vendor: "redis", product: "redis"},
	":redis":        {vendor: "redis", product: "redis"},
	":redis-server": {vendor: "redis", product: "redis"},
	":redis-tools":  {vendor: "redis", product: "redis"},
}

// CuratedProducts returns the set of canonical (vendor, product) pairs the
// scanner's matcher can actually resolve, derived from cpeTable. The NVD index
// generator (internal/nvd/gen) uses this as its allowlist so the curated index
// only contains CVEs the scanner can match — a CVE for any other product is dead
// weight the matcher would never look up. Keys are lowercase [vendor, product].
//
// Extending cpeTable automatically widens this set; re-run `make gen-nvd` to pull
// the newly-covered products into the index.
func CuratedProducts() map[[2]string]bool {
	set := make(map[[2]string]bool, len(cpeTable))
	for _, c := range cpeTable {
		set[[2]string{strings.ToLower(c.vendor), strings.ToLower(c.product)}] = true
	}
	return set
}

// normaliseCPE returns the canonical (vendor, product) pair for matching.
// Tries the exact "vendor:product" key first, then falls back to ":product"
// (unknown vendor), and finally returns the input lowercased.
func normaliseCPE(vendor, product string) (string, string) {
	v := strings.ToLower(vendor)
	p := strings.ToLower(product)

	// Try exact match.
	if entry, ok := cpeTable[v+":"+p]; ok {
		return entry.vendor, entry.product
	}
	// Try product-only match (blank vendor).
	if entry, ok := cpeTable[":"+p]; ok {
		return entry.vendor, entry.product
	}
	// Return inputs as-is.
	return v, p
}
