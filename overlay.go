package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ── Step 1: Locate devcontainer.json ─────────────────────────────────────────

// findDevcontainerJSON walks up from cwd looking for
//
//	.devcontainer/devcontainer.json
//	.devcontainer.json
//
// It stops at a git root (.git exists) or the filesystem root.
func findDevcontainerJSON() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot determine working directory: %w", err)
	}
	for {
		candidates := []string{
			filepath.Join(dir, ".devcontainer", "devcontainer.json"),
			filepath.Join(dir, ".devcontainer.json"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c, nil
			}
		}
		// Stop at a git root so we don't wander into a parent repo.
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // filesystem root
		}
		dir = parent
	}
	return "", fmt.Errorf("no devcontainer.json found (searched up to %s)", dir)
}

// ── Step 2: Parse JSONC ───────────────────────────────────────────────────────

// stripJSONC removes // line comments and /* */ block comments from JSONC
// without corrupting string literals (including strings containing "//").
func stripJSONC(data []byte) []byte {
	out := make([]byte, 0, len(data))
	i, n := 0, len(data)
	for i < n {
		switch {
		case data[i] == '"':
			// String literal — copy verbatim until the closing unescaped quote.
			out = append(out, data[i])
			i++
			for i < n {
				if data[i] == '\\' && i+1 < n {
					// Escaped character — copy both bytes and keep going.
					out = append(out, data[i], data[i+1])
					i += 2
					continue
				}
				ch := data[i]
				out = append(out, ch)
				i++
				if ch == '"' {
					break
				}
			}

		case i+1 < n && data[i] == '/' && data[i+1] == '/':
			// Line comment — skip through to (but not including) the newline
			// so column-tracking stays sane.
			for i < n && data[i] != '\n' {
				i++
			}

		case i+1 < n && data[i] == '/' && data[i+1] == '*':
			// Block comment — skip until closing */.
			i += 2
			for i+1 < n {
				if data[i] == '*' && data[i+1] == '/' {
					i += 2
					break
				}
				i++
			}

		default:
			out = append(out, data[i])
			i++
		}
	}
	return out
}

// parseDevcontainerJSON reads a (possibly JSONC) devcontainer config and
// returns it as a raw-message map so unknown fields are preserved verbatim.
func parseDevcontainerJSON(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	cleaned := stripJSONC(data)
	var result map[string]json.RawMessage
	if err := json.Unmarshal(cleaned, &result); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return result, nil
}

// ── Step 3a: Build the PEM bundle ────────────────────────────────────────────

// buildPEMBundle encodes a list of x509 certificates into a single PEM bundle.
func buildPEMBundle(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return buf.Bytes()
}

// ── Step 3b: Write the Feature directory ─────────────────────────────────────

type featureMount struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

type featureManifest struct {
	ID               string         `json:"id"`
	Version          string         `json:"version"`
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	Mounts           []featureMount `json:"mounts"`
	PostStartCommand string         `json:"postStartCommand,omitempty"`
}

// install.sh is written into the Feature directory and run inside the container.
// It expects the CA bundle at /tmp/certsync-bundle.pem, delivered via the bind
// mount declared in devcontainer-feature.json.
//
// Distro support:
//   - Debian/Ubuntu: update-ca-certificates (copies to /usr/local/share/ca-certificates/)
//   - RHEL/UBI/Fedora: update-ca-trust       (copies to /etc/pki/ca-trust/source/anchors/)
//   - Neither found: warns loudly and exits 0 so the container still starts.
const installSh = `#!/bin/sh
set -e

# Write the dynamic, idempotent injector script to /usr/local/bin/certsync-inject
cat << 'EOF' > /usr/local/bin/certsync-inject
#!/bin/sh
set -e

# Sudo self-escalation logic
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo > /dev/null 2>&1; then
        if sudo -n true 2>/dev/null; then
            exec sudo "$0" "$@"
        else
            echo "certsync: WARNING: sudo requires password. Skipping root-level operations."
        fi
    else
        echo "certsync: WARNING: running as non-root and sudo is not installed. Skipping root-level operations."
    fi
fi

CA_PEM="/tmp/certsync-bundle.pem"

# 1. Update OS System Trust Store (Idempotent)
if [ "$(id -u)" -eq 0 ] && [ -f "$CA_PEM" ]; then
    if command -v update-ca-certificates > /dev/null 2>&1; then
        cp "$CA_PEM" /usr/local/share/ca-certificates/certsync.crt
        update-ca-certificates
        CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
    elif command -v update-ca-trust > /dev/null 2>&1; then
        cp "$CA_PEM" /etc/pki/ca-trust/source/anchors/certsync.crt
        update-ca-trust
        CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
    else
        echo "certsync: WARNING: no CA update command found" >&2
        CA_BUNDLE=""
    fi

    if [ -n "$CA_BUNDLE" ]; then
        for var in "NODE_EXTRA_CA_CERTS=$CA_BUNDLE" "SSL_CERT_FILE=$CA_BUNDLE" "REQUESTS_CA_BUNDLE=$CA_BUNDLE" "NODE_USE_SYSTEM_CA=1"; do
            key="${var%%=*}"
            if ! grep -q "^$key=" /etc/environment; then
                echo "$var" >> /etc/environment
            fi
        done
    fi
fi

# 2. Scan and Wrap Node.js Binaries (Idempotent & Portable Shim)
find_node_bins() {
    # System paths
    if [ "$(id -u)" -eq 0 ]; then
        for p in /usr/bin/node /usr/local/bin/node; do
            if [ -f "$p" ] && [ ! -L "$p" ]; then
                echo "$p"
            fi
        done
    fi
    # Version managers (NVM, FNM, Volta)
    for home_dir in /root /home/*; do
        [ -d "$home_dir" ] || continue
        if [ -d "$home_dir/.nvm/versions/node" ]; then
            find "$home_dir/.nvm/versions/node" -type f -name "node" 2>/dev/null || true
        fi
        if [ -d "$home_dir/.fnm/node-versions" ]; then
            find "$home_dir/.fnm/node-versions" -type f -name "node" 2>/dev/null || true
        fi
        if [ -d "$home_dir/.volta/tools/image/node" ]; then
            find "$home_dir/.volta/tools/image/node" -type f -name "node" 2>/dev/null || true
        fi
    done
}

for node_bin in $(find_node_bins); do
    if [ -f "$node_bin" ] && [ ! -L "$node_bin" ]; then
        # Check if already wrapped
        if head -n 3 "$node_bin" | grep -q "CERTSYNC_SHIM"; then
            continue
        fi

        if [ -w "$node_bin" ] && [ -w "$(dirname "$node_bin")" ]; then
            echo "certsync: Wrapping $node_bin..."
            dir_name="$(dirname "$node_bin")"
            real_bin="$dir_name/node-real"

            mv "$node_bin" "$real_bin"

            cat << 'SHIM' > "$node_bin"
#!/bin/sh
# CERTSYNC_SHIM
export NODE_USE_SYSTEM_CA=1
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
    export NODE_EXTRA_CA_CERTS=/etc/pki/tls/certs/ca-bundle.crt
fi
DIR="$(dirname "$0")"
exec "$DIR/node-real" "$@"
SHIM
            chmod +x "$node_bin"
        else
            echo "certsync: Cannot write to $node_bin, skipping wrapping."
        fi
    fi
done

# 3. Scan and Inject Java Keystore (cacerts) (Idempotent)
find_cacerts() {
    find /usr/lib/jvm /opt /usr/local -name "cacerts" 2>/dev/null || true
    for home_dir in /root /home/*; do
        [ -d "$home_dir" ] || continue
        if [ -d "$home_dir/.sdkman/candidates/java" ]; then
            find "$home_dir/.sdkman/candidates/java" -name "cacerts" 2>/dev/null || true
        fi
    done
}

if [ -f "$CA_PEM" ] && command -v keytool > /dev/null 2>&1; then
    for cacert in $(find_cacerts); do
        if [ -w "$cacert" ]; then
            # Always delete first so we update the keystore if the bundle has changed
            keytool -delete -alias certsync -keystore "$cacert" -storepass changeit >/dev/null 2>&1 || true
            echo "certsync: Importing CA into Java trust store: $cacert..."
            keytool -importcert -trustcacerts -file "$CA_PEM" -keystore "$cacert" -storepass changeit -noprompt -alias certsync >/dev/null 2>&1 || true
        else
            echo "certsync: Cannot write to Java trust store $cacert, skipping."
        fi
    done
fi
EOF

chmod +x /usr/local/bin/certsync-inject

# Run immediately during build
/usr/local/bin/certsync-inject || true
`

// writeFeatureDir creates ~/.certsync/ca-inject/ and writes:
//
//	devcontainer-feature.json  — Feature manifest with a bind mount for the bundle
//	install.sh                 — copies the bundle into the container trust store
//	bundle.pem                 — the PEM bundle (bind-mounted source)
//
// Returns the absolute paths to the feature dir and the bundle file.
func writeFeatureDir(home string, pemBundle []byte) (featureDir, bundlePath string, err error) {
	featureDir = filepath.Join(home, ".certsync", "ca-inject")
	if err = os.MkdirAll(featureDir, 0700); err != nil {
		return "", "", fmt.Errorf("creating feature dir: %w", err)
	}

	// Write the PEM bundle — the mount source on the host.
	bundlePath = filepath.Join(featureDir, "bundle.pem")
	if err = os.WriteFile(bundlePath, pemBundle, 0600); err != nil {
		return "", "", fmt.Errorf("writing bundle.pem: %w", err)
	}

	// Write install.sh.
	if err = os.WriteFile(filepath.Join(featureDir, "install.sh"), []byte(installSh), 0700); err != nil {
		return "", "", fmt.Errorf("writing install.sh: %w", err)
	}

	// Build and write devcontainer-feature.json.
	// The mount source is the absolute path to bundle.pem on the host so the
	// Feature is fully self-describing — no path info leaks into the overlay.
	manifest := featureManifest{
		ID:          "ca-inject",
		Version:     "1.0.0",
		Name:        "CertSync CA Injection",
		Description: "Injects host CA certificates into the container trust store",
		Mounts: []featureMount{
			{
				Source: bundlePath,
				Target: "/tmp/certsync-bundle.pem",
				Type:   "bind",
			},
		},
		PostStartCommand: "/usr/local/bin/certsync-inject",
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshaling feature manifest: %w", err)
	}
	if err = os.WriteFile(filepath.Join(featureDir, "devcontainer-feature.json"), manifestJSON, 0600); err != nil {
		return "", "", fmt.Errorf("writing devcontainer-feature.json: %w", err)
	}

	return featureDir, bundlePath, nil
}

// ── Step 3c: Build the overlay JSON ─────────────────────────────────────────

// buildOverlayJSON clones the original devcontainer config and injects the
// certsync Feature. The feature key is the absolute path to the feature dir
// (devcontainer CLI's syntax for local features).
//
// Rules:
//   - If "features" exists, our key is merged in (preserving existing entries).
//   - "overrideFeatureInstallOrder" is always written: our key is prepended to
//     an existing array, or a new single-element array is created. This ensures
//     CAs are trusted before any other feature's network operations.
//   - All other fields are carried through unchanged.
func buildOverlayJSON(original map[string]json.RawMessage, featureDir string) ([]byte, error) {
	overlay := make(map[string]json.RawMessage, len(original)+1)
	for k, v := range original {
		overlay[k] = v
	}

	// Merge into the features object.
	existingFeatures := make(map[string]json.RawMessage)
	if raw, ok := overlay["features"]; ok {
		if err := json.Unmarshal(raw, &existingFeatures); err != nil {
			return nil, fmt.Errorf("parsing existing features: %w", err)
		}
	}
	existingFeatures[featureDir] = json.RawMessage(`{}`)
	featuresJSON, err := json.Marshal(existingFeatures)
	if err != nil {
		return nil, fmt.Errorf("marshaling features: %w", err)
	}
	overlay["features"] = featuresJSON

	// Always write overrideFeatureInstallOrder — create it if absent — so
	// certsync CAs land first and other features' network calls can trust them.
	keyJSON, _ := json.Marshal(featureDir)
	if raw, ok := overlay["overrideFeatureInstallOrder"]; ok {
		var order []json.RawMessage
		if err := json.Unmarshal(raw, &order); err != nil {
			return nil, fmt.Errorf("parsing overrideFeatureInstallOrder: %w", err)
		}
		order = append([]json.RawMessage{keyJSON}, order...)
		orderJSON, _ := json.Marshal(order)
		overlay["overrideFeatureInstallOrder"] = orderJSON
	} else {
		overlay["overrideFeatureInstallOrder"] = json.RawMessage("[" + string(keyJSON) + "]")
	}

	body, err := json.MarshalIndent(overlay, "", "  ")
	if err != nil {
		return nil, err
	}

	// Prepend a JSONC comment so the file is self-documenting.
	header := []byte("// Auto-generated by certsync — do not edit. Delete this file to discard CA injection.\n")
	return append(header, body...), nil
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

// runOverlay is called by runUp after the user has confirmed profile selection.
// It drives all overlay work and returns an error on failure; deferred cleanup
// runs on both success and failure paths so the caller never needs to
// call os.Exit from within this function.
func runOverlay(selectedCerts []*x509.Certificate) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	// Build the PEM bundle from selected certificates.
	pemBundle := buildPEMBundle(selectedCerts)
	if len(pemBundle) == 0 {
		return fmt.Errorf("no valid certificates to bundle")
	}
	fmt.Printf("Bundling %d certificates...\n", len(selectedCerts))

	// Write the Feature directory. It lives at ~/.certsync/ca-inject/ and is
	// intentionally NOT cleaned up after devcontainer up returns — Docker may
	// still be executing that build layer when cmd.Run() comes back, and
	// removing bundle.pem mid-layer would corrupt the image build.
	// The directory is overwritten on the next `certsync up` run anyway.
	featureDir, _, err := writeFeatureDir(home, pemBundle)
	if err != nil {
		return err
	}

	// Locate the project's devcontainer.json.
	dcPath, err := findDevcontainerJSON()
	if err != nil {
		return fmt.Errorf("%w\n  Make sure you're running certsync from within a devcontainer project", err)
	}
	fmt.Printf("Found devcontainer config: %s\n", dcPath)

	// Parse it (JSONC → raw map).
	original, err := parseDevcontainerJSON(dcPath)
	if err != nil {
		return fmt.Errorf("parsing devcontainer.json: %w", err)
	}

	// Build the overlay JSON.
	overlayJSON, err := buildOverlayJSON(original, featureDir)
	if err != nil {
		return fmt.Errorf("building overlay: %w", err)
	}

	// Determine the project root: if devcontainer.json lives inside
	// .devcontainer/, the project root is one level up.
	projectDir := filepath.Dir(dcPath)
	if filepath.Base(projectDir) == ".devcontainer" {
		projectDir = filepath.Dir(projectDir)
	}

	// Write the overlay file at the project root.
	overlayPath := filepath.Join(projectDir, ".certsync-overlay.jsonc")
	if err := os.WriteFile(overlayPath, overlayJSON, 0600); err != nil {
		return fmt.Errorf("writing overlay file: %w", err)
	}
	fmt.Printf("Wrote overlay:             %s\n", overlayPath)

	// Hand off to the devcontainer CLI.
	fmt.Println("\n\x1b[1;36mStarting devcontainer...\x1b[0m")
	cmd := exec.Command("devcontainer", "up",
		"--workspace-folder", projectDir,
		"--config", overlayPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Leave the overlay file in place so the user can inspect what was
		// generated and diagnose why devcontainer up failed.
		fmt.Printf("\n\x1b[1;33mOverlay preserved for inspection: %s\x1b[0m\n", overlayPath)
		return fmt.Errorf("devcontainer up: %w", err)
	}

	// Success — overlay is no longer needed; Docker has already processed it.
	_ = os.Remove(overlayPath)
	return nil
}

