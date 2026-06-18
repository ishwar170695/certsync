package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
)

// Profile represents a grouped set of certificates (e.g. system roots, MITM proxies).
type Profile struct {
	Name        string
	Description string
	Certs       []*x509.Certificate
	IsMITM      bool
}

// JSONProfile represents a profile serialized to JSON.
type JSONProfile struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsMITM      bool     `json:"is_mitm"`
	Certs       []string `json:"certs"`
}

// JSONData represents the root object of the profiles.json database.
type JSONData struct {
	Version   int           `json:"version"`
	ScannedAt string        `json:"scanned_at"`
	Profiles  []JSONProfile `json:"profiles"`
}

// certKey returns a unique identifier for a certificate.
func certKey(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) > 0 {
		return hex.EncodeToString(cert.SubjectKeyId)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Deduplicate removes duplicate certificates from a slice using certKey.
func Deduplicate(certs []*x509.Certificate) []*x509.Certificate {
	seen := make(map[string]bool)
	var unique []*x509.Certificate
	for _, cert := range certs {
		key := certKey(cert)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, cert)
		}
	}
	return unique
}

// matchesHeuristics checks if a certificate matches corporate MITM or custom/private CA characteristics.
func matchesHeuristics(cert *x509.Certificate) bool {
	score := 0

	// Heuristic 1: Known corporate security/MITM vendor strings in Subject or Issuer O/CN
	vendors := []string{"zscaler", "palo alto", "netskope", "bluecoat", "cisco umbrella", "forcepoint"}
	hasVendor := false
	for _, vendor := range vendors {
		if containsIgnoreCase(cert.Subject.Organization, vendor) ||
			containsIgnoreCaseStr(cert.Subject.CommonName, vendor) ||
			containsIgnoreCase(cert.Issuer.Organization, vendor) ||
			containsIgnoreCaseStr(cert.Issuer.CommonName, vendor) {
			hasVendor = true
			break
		}
	}
	if hasVendor {
		score++
	}

	// Heuristic 2: Corporate internal naming patterns in Subject/Issuer CN
	internalPatterns := []string{"corp", "internal", "proxy", "mitm", "inspect"}
	hasInternal := false
	for _, pattern := range internalPatterns {
		if containsIgnoreCaseStr(cert.Subject.CommonName, pattern) ||
			containsIgnoreCaseStr(cert.Issuer.CommonName, pattern) {
			hasInternal = true
			break
		}
	}
	if hasInternal {
		score++
	}

	// Heuristic 3: Self-signed root with validity < 10 years
	isSelfSigned := bytes.Equal(cert.RawSubject, cert.RawIssuer)
	if cert.IsCA && isSelfSigned {
		validityLimit := cert.NotBefore.AddDate(10, 0, 0)
		if cert.NotAfter.Before(validityLimit) {
			score++
		}
	}

	// Heuristic 4: Weak RSA key size for a Root CA (RSA < 2048 is unusual for modern Root CAs)
	if cert.IsCA && isSelfSigned {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if rsaKey.N.BitLen() < 2048 {
				score++
			}
		}
	}

	// Heuristic 5: Lack of both CRL Distribution Points and OCSP Servers (common for corporate/internal certs)
	if len(cert.CRLDistributionPoints) == 0 && len(cert.OCSPServer) == 0 {
		score++
	}

	return score >= 2
}

// isOSVendor returns true if the organization represents a major OS/platform vendor trust store.
func isOSVendor(org string) bool {
	orgLower := strings.ToLower(org)
	return strings.Contains(orgLower, "apple") ||
		strings.Contains(orgLower, "microsoft") ||
		strings.Contains(orgLower, "google") ||
		strings.Contains(orgLower, "android")
}

// GroupCertificates clusters deduplicated certificates into Profiles.
func GroupCertificates(certs []*x509.Certificate) []Profile {
	mitmGroups := make(map[string][]*x509.Certificate)
	vendorGroups := make(map[string][]*x509.Certificate)
	var systemDefaultCerts []*x509.Certificate

	for _, cert := range certs {
		org := "Unknown"
		if len(cert.Issuer.Organization) > 0 {
			org = cert.Issuer.Organization[0]
		} else if cert.Issuer.CommonName != "" {
			org = cert.Issuer.CommonName
		}

		if matchesHeuristics(cert) {
			mitmGroups[org] = append(mitmGroups[org], cert)
		} else if isOSVendor(org) {
			vendorGroups[org] = append(vendorGroups[org], cert)
		} else {
			systemDefaultCerts = append(systemDefaultCerts, cert)
		}
	}

	var profiles []Profile

	// Add MITM groups in deterministic sorted order
	var mitmKeys []string
	for org := range mitmGroups {
		mitmKeys = append(mitmKeys, org)
	}
	sort.Strings(mitmKeys)
	for _, org := range mitmKeys {
		groupCerts := mitmGroups[org]
		profiles = append(profiles, Profile{
			Name:        org + " Proxy",
			Description: "likely MITM proxy",
			Certs:       groupCerts,
			IsMITM:      true,
		})
	}

	// Add OS Vendor groups in deterministic sorted order
	var vendorKeys []string
	for org := range vendorGroups {
		vendorKeys = append(vendorKeys, org)
	}
	sort.Strings(vendorKeys)
	for _, org := range vendorKeys {
		groupCerts := vendorGroups[org]
		name := org
		if !strings.Contains(strings.ToLower(org), "root") && !strings.Contains(strings.ToLower(org), "ca") {
			name = org + " Root CA"
		}
		profiles = append(profiles, Profile{
			Name:        name,
			Description: "system roots",
			Certs:       groupCerts,
			IsMITM:      false,
		})
	}

	// Add System Default group if it contains any certificates
	if len(systemDefaultCerts) > 0 {
		profiles = append(profiles, Profile{
			Name:        "System Default",
			Description: "standard CAs",
			Certs:       systemDefaultCerts,
			IsMITM:      false,
		})
	}

	return profiles
}

func containsIgnoreCase(slice []string, needle string) bool {
	needle = strings.ToLower(needle)
	for _, s := range slice {
		if strings.Contains(strings.ToLower(s), needle) {
			return true
		}
	}
	return false
}

func containsIgnoreCaseStr(s, needle string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(needle))
}

func printUsage() {
	fmt.Println("\x1b[1;36mCertSync - Host Certificate Synchronizer\x1b[0m")
	fmt.Println("\nUsage:")
	fmt.Println("  certsync init    Scan host certificate stores and save to ~/.certsync/profiles.json")
	fmt.Println("  certsync up      Select trust profiles and inject them into your devcontainer")
	fmt.Println("  certsync help    Show this help information")
}

func runInit() {
	if len(os.Args) > 2 {
		arg := os.Args[2]
		if arg == "-h" || arg == "--help" || arg == "help" {
			fmt.Println("Usage: certsync init")
			fmt.Println("\nScans host certificate stores and saves the detected profiles to ~/.certsync/profiles.json.")
			return
		}
	}

	enableAnsi()

	fmt.Println("\x1b[1;36mCertSync - Initializing host profiles\x1b[0m")
	fmt.Println("Scanning host certificate stores...")

	rawCerts, err := GetHostCertificates()
	if err != nil {
		fmt.Printf("\x1b[1;31mError scanning certificates: %v\x1b[0m\n", err)
		os.Exit(1)
	}

	uniqueCerts := Deduplicate(rawCerts)
	profiles := GroupCertificates(uniqueCerts)

	if len(profiles) == 0 {
		fmt.Println("\n\x1b[1;33mNo CA certificates found on the host system.\x1b[0m")
		os.Exit(0)
	}

	fmt.Printf("\nFound %d unique CA certificates. Grouped into %d profiles.\n", len(uniqueCerts), len(profiles))

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("\x1b[1;31mError getting user home directory: %v\x1b[0m\n", err)
		os.Exit(1)
	}

	certSyncDir := filepath.Join(home, ".certsync")
	if err := os.MkdirAll(certSyncDir, 0755); err != nil {
		fmt.Printf("\x1b[1;31mError creating directory %s: %v\x1b[0m\n", certSyncDir, err)
		os.Exit(1)
	}

	// Build JSON structure
	var jsonProfiles []JSONProfile
	for _, p := range profiles {
		var certStrings []string
		for _, cert := range p.Certs {
			pemBlock := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			certStrings = append(certStrings, string(pemBlock))
		}
		jsonProfiles = append(jsonProfiles, JSONProfile{
			Name:        p.Name,
			Description: p.Description,
			IsMITM:      p.IsMITM,
			Certs:       certStrings,
		})
	}

	data := JSONData{
		Version:   1,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Profiles:  jsonProfiles,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("\x1b[1;31mError marshaling profiles to JSON: %v\x1b[0m\n", err)
		os.Exit(1)
	}

	profilesPath := filepath.Join(certSyncDir, "profiles.json")
	if err := os.WriteFile(profilesPath, jsonData, 0600); err != nil {
		fmt.Printf("\x1b[1;31mError writing profiles.json: %v\x1b[0m\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n\x1b[1;32m✔ Successfully wrote profiles to %s\x1b[0m\n", profilesPath)
}

func runUp() {
	if len(os.Args) > 2 {
		arg := os.Args[2]
		if arg == "-h" || arg == "--help" || arg == "help" {
			fmt.Println("Usage: certsync up")
			fmt.Println("\nLoads profiles from ~/.certsync/profiles.json, prompts for trust-profile selection,")
			fmt.Println("then generates a devcontainer overlay to inject the chosen CAs into your container.")
			return
		}
	}

	enableAnsi()

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("\x1b[1;31mError getting user home directory: %v\x1b[0m\n", err)
		os.Exit(1)
	}

	profilesPath := filepath.Join(home, ".certsync", "profiles.json")
	jsonData, err := os.ReadFile(profilesPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("\x1b[1;31mError: profiles database not found at %s.\nRun 'certsync init' first to scan and save profiles.\x1b[0m\n", profilesPath)
		} else {
			fmt.Printf("\x1b[1;31mError reading profiles: %v\x1b[0m\n", err)
		}
		os.Exit(1)
	}

	var data JSONData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		fmt.Printf("\x1b[1;31mError parsing profiles JSON: %v\x1b[0m\n", err)
		os.Exit(1)
	}

	// Check scanned_at for staleness (older than 30 days)
	scannedAt, err := time.Parse(time.RFC3339, data.ScannedAt)
	if err == nil {
		if time.Since(scannedAt) > 30*24*time.Hour {
			fmt.Printf("\x1b[1;33m⚠ Warning: Profiles database is stale (scanned at %s).\nIt is recommended to run 'certsync init' to update profiles.\x1b[0m\n\n", scannedAt.Local().Format("2006-01-02 15:04:05"))
		}
	}

	// Reconstruct Profiles from JSONData
	var profiles []Profile
	var totalCertsCount int
	for _, jp := range data.Profiles {
		var certs []*x509.Certificate
		for _, certPEM := range jp.Certs {
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil || block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
		profiles = append(profiles, Profile{
			Name:        jp.Name,
			Description: jp.Description,
			Certs:       certs,
			IsMITM:      jp.IsMITM,
		})
		totalCertsCount += len(certs)
	}

	if len(profiles) == 0 {
		fmt.Println("\x1b[1;33mNo profiles found in database.\x1b[0m")
		os.Exit(0)
	}

	fmt.Printf("Loaded %d profiles (%d total certificates) from %s\n\n", len(profiles), totalCertsCount, profilesPath)

	allMitm := false
	if len(os.Args) > 2 {
		for _, arg := range os.Args[2:] {
			if arg == "--all-mitm" {
				allMitm = true
				break
			}
		}
	}

	var selectedProfiles []Profile
	if allMitm {
		fmt.Println("Running in non-interactive mode (--all-mitm). Automatically selecting MITM and System Default profiles.")
		for _, p := range profiles {
			if p.IsMITM || p.Name == "System Default" {
				selectedProfiles = append(selectedProfiles, p)
			}
		}
	} else {
		// Initialize selected states — MITM proxies and System Default are pre-checked
		checked := make([]bool, len(profiles))
		for i, p := range profiles {
			if p.IsMITM || p.Name == "System Default" {
				checked[i] = true
			}
		}

		var err error
		selectedProfiles, err = promptUserProfiles(profiles, checked)
		if err != nil {
			if err.Error() == "cancelled" {
				fmt.Println("\n\x1b[1;31mOperation cancelled.\x1b[0m")
				os.Exit(0)
			}
			fmt.Printf("\n\x1b[1;31mError during selection: %v\x1b[0m\n", err)
			os.Exit(1)
		}
	}

	if len(selectedProfiles) == 0 {
		fmt.Println("\x1b[1;33mNo profiles selected. Nothing to do.\x1b[0m")
		os.Exit(0)
	}

	// Collect certs from selected profiles
	var selectedCerts []*x509.Certificate
	for _, p := range selectedProfiles {
		selectedCerts = append(selectedCerts, p.Certs...)
	}

	// Generate the devcontainer overlay and exec devcontainer up.
	// runOverlay defers cleanup of the feature dir and overlay file itself,
	// so defers fire correctly even if an error is returned here.
	if err := runOverlay(selectedCerts); err != nil {
		fmt.Printf("\n\x1b[1;31mError: %v\x1b[0m\n", err)
		os.Exit(1)
	}
	fmt.Println("\n\x1b[1;32m✔ devcontainer is up with injected CA certificates.\x1b[0m")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "init":
		runInit()
	case "up":
		runUp()
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}


func promptUserProfiles(profiles []Profile, checked []bool) ([]Profile, error) {
	fmt.Println("Which profiles should containers trust? (Use arrow keys/JK to move, Space to toggle, Enter to confirm)")

	numLines := len(profiles)
	cursor := 0

	// Put terminal in raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to make raw terminal: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Hide cursor
	fmt.Print("\x1b[?25l")
	defer fmt.Print("\x1b[?25h")

	drawMenu := func() {
		for i, p := range profiles {
			prefix := "  "
			if i == cursor {
				prefix = "\x1b[1;36m▸ \x1b[0m"
			}

			box := "\x1b[90m[ ]\x1b[0m"
			if checked[i] {
				box = "\x1b[1;32m[✔]\x1b[0m"
			}

			nameColor := "\x1b[37m"
			if i == cursor {
				nameColor = "\x1b[1;37m"
			}
			fmt.Printf("\r\x1b[2K%s%s %s%-28s\x1b[0m \x1b[90m(%d certs — %s)\x1b[0m\r\n", prefix, box, nameColor, p.Name, len(p.Certs), p.Description)
		}
	}

	drawMenu()

	for {
		key, err := readKey()
		if err != nil {
			return nil, err
		}

		if key == "ctrl+c" {
			return nil, fmt.Errorf("cancelled")
		}

		if key == "enter" {
			break
		}

		if key == "space" {
			checked[cursor] = !checked[cursor]
		}

		if key == "up" {
			cursor--
			if cursor < 0 {
				cursor = numLines - 1
			}
		}

		if key == "down" {
			cursor++
			if cursor >= numLines {
				cursor = 0
			}
		}

		// Move cursor back to the top of the menu and redraw
		fmt.Printf("\x1b[%dA", numLines)
		drawMenu()
	}

	var selected []Profile
	for i, isChecked := range checked {
		if isChecked {
			selected = append(selected, profiles[i])
		}
	}
	return selected, nil
}

func readKey() (string, error) {
	var buf [1]byte
	_, err := os.Stdin.Read(buf[:])
	if err != nil {
		return "", err
	}
	if buf[0] == 0x03 { // Ctrl+C
		return "ctrl+c", nil
	}
	if buf[0] == '\r' || buf[0] == '\n' {
		return "enter", nil
	}
	if buf[0] == ' ' {
		return "space", nil
	}
	if buf[0] == 'k' || buf[0] == 'K' {
		return "up", nil
	}
	if buf[0] == 'j' || buf[0] == 'J' {
		return "down", nil
	}
	if buf[0] == 0x1b {
		// Escape sequence
		_, err = os.Stdin.Read(buf[:])
		if err != nil {
			return "escape", nil
		}
		if buf[0] == '[' {
			_, err = os.Stdin.Read(buf[:])
			if err != nil {
				return "escape", nil
			}
			switch buf[0] {
			case 'A':
				return "up", nil
			case 'B':
				return "down", nil
			}
		}
	}
	// Unrecognized key, return empty string (ignored by the caller loop)
	return "", nil
}
