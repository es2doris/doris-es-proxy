package proxy

import (
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzRepositoryURLValidator(f *testing.F) {
	seeds := []struct {
		rawURL      string
		allowMode   uint8
		usePathRepo bool
	}{
		{"http://snapshot.test1/catalog", 0, true},
		{"https://snapshot.test/sub", 0, true},
		{"http://snapshot.unknown/sub", 0, true},
		{"http://127.0.0.1:8080/repo", 1, true},
		{"http://127.0.0.1:9200/", 0, true},
		{"http://127.0.0.1:9200/", 2, true},
		{"http://169.254.169.254/latest/meta-data/", 2, true},
		{"http://[::ffff:169.254.169.254]/latest/meta-data/", 2, true},
		{"http://[fd00:ec2::254]/latest/meta-data/", 2, true},
		{"http://metadata.google.internal/computeMetadata/v1/", 2, true},
		{"http://[::1]:9200/", 2, true},
		{"http://[::ffff:127.0.0.1]/", 2, true},
		{"http://10.0.0.1/", 2, true},
		{"http://172.16.0.1/", 2, true},
		{"http://192.168.1.1/", 2, true},
		{"http://100.64.0.1/", 2, true},
		{"http://0.0.0.0/", 2, true},
		{"http://localhost:9200/", 2, true},
		{"http://2130706433/", 2, true},
		{"http://0177.0.0.1/", 2, true},
		{"http://0x7f000001/", 2, true},
		{"http://127.1/", 2, true},
		{"http://snapshot.test@127.0.0.1/", 0, true},
		{"https://user:pass@snapshot.test/", 0, true},
		{"http://snapshot.test/a/../b", 0, true},
		{"http://snapshot.test/%2e%2e/secret", 0, true},
		{"http://snapshot.test/?q=1", 0, true},
		{"http://snapshot.test/#frag", 0, true},
		{"http://snapshot.test\\\x00", 0, true},
		{"file:///etc/passwd", 3, false},
		{"file:///etc/passwd", 3, true},
		{"file://localhost/etc/passwd", 3, true},
		{"file://etc/passwd", 3, true},
		{"file:///tmp/../etc/passwd", 3, true},
		{"file:///repo/ok", 3, true},
		{"file:///repo/escape", 3, true},
		{"ftp://snapshot.test/repo", 2, true},
		{"gopher://127.0.0.1:6379/_INFO", 2, true},
		{"jar:file:///etc/passwd!/", 3, true},
		{"", 0, true},
	}
	for _, s := range seeds {
		f.Add(s.rawURL, s.allowMode, s.usePathRepo)
	}

	rootBase := f.TempDir()
	outsideBase := f.TempDir()
	pathRepoDir := filepath.Join(rootBase, "repo_root")
	subSafe := filepath.Join(pathRepoDir, "safe")
	if err := os.MkdirAll(subSafe, 0o750); err != nil {
		f.Fatalf("mkdir safe dir: %v", err)
	}
	escapeLink := filepath.Join(pathRepoDir, "escape_symlink")
	_ = os.Symlink(outsideBase, escapeLink)

	resolvedRoot, err := resolveSymlinkBestEffortR65(pathRepoDir)
	if err != nil {
		f.Fatalf("resolve root: %v", err)
	}
	resolvedOutside, err := resolveSymlinkBestEffortR65(outsideBase)
	if err != nil {
		f.Fatalf("resolve outside: %v", err)
	}
	filePrefix := "file:///" + strings.TrimPrefix(filepath.ToSlash(pathRepoDir), "/") + "/"

	f.Fuzz(func(t *testing.T, rawURL string, allowMode uint8, usePathRepo bool) {
		if len(rawURL) > 512 {
			return
		}
		// Skip OS autofs/device virtual directories that can block Lstat/EvalSymlinks in kernel VFS.
		lowerRaw := strings.ToLower(strings.TrimSpace(rawURL))
		trimmedPath := lowerRaw
		if u, uErr := url.Parse(strings.TrimSpace(rawURL)); uErr == nil && u.Path != "" {
			trimmedPath = strings.ToLower(u.Path)
		}
		cleanCheck := strings.ToLower(filepath.ToSlash(filepath.Clean("/" + strings.TrimLeft(trimmedPath, "/"))))
		for _, pfx := range []string{"/dev", "/net", "/home", "/volumes", "/network", "/proc", "/sys", "/system"} {
			if cleanCheck == pfx || strings.HasPrefix(cleanCheck, pfx+"/") ||
				lowerRaw == "file://"+pfx || strings.HasPrefix(lowerRaw, "file://"+pfx+"/") {
				return
			}
		}

		var pathRepos []string
		if usePathRepo {
			pathRepos = []string{resolvedRoot}
		}
		var allowed []string
		switch allowMode % 5 {
		case 0:
			allowed = []string{"http://snapshot.test*", "https://snapshot.test*", filePrefix + "*"}
		case 1:
			allowed = []string{"http://127.0.0.1:8080/*", "http://snapshot.test*", filePrefix + "*"}
		case 2:
			// Overly broad wildcards must still fail SSRF checks for loopback/RFC1918/IMDS/metadata.
			allowed = []string{"http://*", "https://*", "*"}
		case 3:
			allowed = []string{"file://*"}
		case 4:
			allowed = nil
		}

		// Substitute sentinel placeholders so fuzz corpus hits real symlink & safe dirs inside TempDir.
		candidate := strings.ReplaceAll(rawURL, "/repo/ok", pathRepoDir+"/safe")
		if strings.Contains(candidate, "/repo/escape") {
			candidate = strings.ReplaceAll(candidate, "/repo/escape", escapeLink)
		}

		res, vErr := parseAndValidateSnapshotRepoURLR65(candidate, pathRepos, allowed)
		if vErr == nil {
			if res == nil {
				t.Fatalf("nil result with nil error for %q", candidate)
			}
			parsed, pErr := url.Parse(strings.TrimSpace(candidate))
			if pErr != nil {
				t.Fatalf("accepted unparseable URL %q: %v", candidate, pErr)
			}
			if parsed.User != nil {
				t.Fatalf("accepted URL with userinfo: %q", candidate)
			}
			if parsed.RawQuery != "" || parsed.Fragment != "" {
				t.Fatalf("accepted URL with query/fragment: %q", candidate)
			}
			switch res.scheme {
			case "file":
				if len(pathRepos) == 0 || len(allowed) == 0 {
					t.Fatalf("accepted file URL without path.repo and allowed_urls: %q", candidate)
				}
				if !isPathContainedR65(res.resolvedFilePath, resolvedRoot) {
					t.Fatalf("file path %q escaped root %q", res.resolvedFilePath, resolvedRoot)
				}
				if isPathContainedR65(res.resolvedFilePath, resolvedOutside) {
					t.Fatalf("file path %q resolved inside outside target %q", res.resolvedFilePath, resolvedOutside)
				}
			case "http", "https":
				if len(allowed) == 0 {
					t.Fatalf("accepted http(s) URL with empty allowlist: %q", candidate)
				}
				host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
				if host == "" || host == "metadata.google.internal" || host == "metadata" {
					t.Fatalf("accepted metadata/empty host: %q", candidate)
				}
				if addr, aErr := netip.ParseAddr(host); aErr == nil {
					u := addr.Unmap()
					if isUnconditionallyBlockedSnapshotHostOrIPR65(host, &u) {
						t.Fatalf("accepted unconditionally blocked IP %q in %q", u.String(), candidate)
					}
					if isBlockedRemoteReindexIPRound62(u) || u.IsLoopback() || u.IsPrivate() {
						if !isIPAuthorizedByExplicitAllowlistR65(u, res) {
							t.Fatalf("accepted unauthorized private/loopback IP %q in %q", u.String(), candidate)
						}
					}
				}
			default:
				t.Fatalf("accepted unexpected scheme %q for %q", res.scheme, candidate)
			}
		}

		// Also exercise FS location containment validator; never allow escape outside path.repo when configured.
		fsResolved, fsErr := validateFSRepoLocationR65(candidate, pathRepos)
		if fsErr == nil && len(pathRepos) > 0 && fsResolved != "" {
			if !isPathContainedR65(fsResolved, resolvedRoot) {
				t.Fatalf("validateFSRepoLocationR65 allowed escape %q outside %q", fsResolved, resolvedRoot)
			}
		}
	})
}
