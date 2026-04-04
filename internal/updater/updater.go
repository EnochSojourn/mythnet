package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	repoOwner = "EnochSojourn"
	repoName  = "mythnet"
)

// Release represents a GitHub release.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset is a release binary.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// CheckUpdate checks for a newer version on GitHub.
func CheckUpdate(currentVersion string) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", repoOwner, repoName)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("check update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")
	if latest <= current {
		return nil, nil // Already up to date
	}

	return &release, nil
}

// SelfUpdate downloads the appropriate binary and replaces the current executable.
func SelfUpdate(release *Release, binaryName string) error {
	suffix := assetSuffix(binaryName)
	if suffix == "" {
		return fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Find matching asset
	var asset *Asset
	for _, a := range release.Assets {
		if strings.Contains(a.Name, suffix) && strings.HasPrefix(a.Name, binaryName) {
			asset = &a
			break
		}
	}
	if asset == nil {
		return fmt.Errorf("no binary found for %s in release %s", suffix, release.TagName)
	}

	fmt.Printf("Downloading %s (%d MB)...\n", asset.Name, asset.Size/(1024*1024))

	// Download
	resp, err := http.Get(asset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	// Write to temp file
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "mythnet-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()

	// Make executable
	if err := os.Chmod(tmpName, 0755); err != nil {
		os.Remove(tmpName)
		return err
	}

	// Replace current binary
	backup := exe + ".bak"
	os.Remove(backup)
	if err := os.Rename(exe, backup); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("backup current binary: %w", err)
	}

	if err := os.Rename(tmpName, exe); err != nil {
		// Restore backup
		os.Rename(backup, exe)
		return fmt.Errorf("replace binary: %w", err)
	}

	os.Remove(backup)
	fmt.Printf("Updated to %s. Restart to apply.\n", release.TagName)
	return nil
}

func assetSuffix(binaryName string) string {
	os := runtime.GOOS
	arch := runtime.GOARCH
	switch {
	case os == "linux" && arch == "amd64":
		return "linux-amd64"
	case os == "linux" && arch == "arm64":
		return "linux-arm64"
	case os == "linux" && arch == "arm":
		return "linux-armv7"
	case os == "darwin" && arch == "amd64":
		return "darwin-amd64"
	case os == "darwin" && arch == "arm64":
		return "darwin-arm64"
	case os == "windows" && arch == "amd64":
		return "windows-amd64"
	default:
		return ""
	}
}
