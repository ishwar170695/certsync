package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeduplicate(t *testing.T) {
	// Create two identical certs and one different cert
	c1 := &x509.Certificate{
		Raw:          []byte("cert1_raw_bytes"),
		SubjectKeyId: []byte("key1"),
	}
	c2 := &x509.Certificate{
		Raw:          []byte("cert1_raw_bytes"),
		SubjectKeyId: []byte("key1"),
	}
	c3 := &x509.Certificate{
		Raw:          []byte("cert3_raw_bytes"),
		SubjectKeyId: []byte("key3"),
	}

	certs := []*x509.Certificate{c1, c2, c3}
	unique := Deduplicate(certs)

	if len(unique) != 2 {
		t.Fatalf("Expected 2 unique certificates, got %d", len(unique))
	}
	if string(unique[0].Raw) != "cert1_raw_bytes" || string(unique[1].Raw) != "cert3_raw_bytes" {
		t.Errorf("Unexpected unique certificates list")
	}
}

func TestMatchesHeuristics(t *testing.T) {
	// 1. A certificate that should match: has corporate vendor name + lacks CRL/OCSP
	cert1 := &x509.Certificate{
		IsCA: true,
		Subject: pkix.Name{
			Organization: []string{"Zscaler Inc"},
		},
		Issuer: pkix.Name{
			Organization: []string{"Zscaler Inc"},
		},
		SerialNumber:           big.NewInt(1),
		CRLDistributionPoints: []string{},
		OCSPServer:             []string{},
	}
	// Matches vendor (score +1) + lacks CRL/OCSP (score +1) = score 2 (matches)
	if !matchesHeuristics(cert1) {
		t.Errorf("Expected cert1 to match heuristics")
	}

	// 2. A certificate that should not match: standard OS vendor
	cert2 := &x509.Certificate{
		IsCA: true,
		Subject: pkix.Name{
			Organization: []string{"Google Trust Services LLC"},
		},
		Issuer: pkix.Name{
			Organization: []string{"Google Trust Services LLC"},
		},
		CRLDistributionPoints: []string{"http://crl.google.com"},
		OCSPServer:             []string{"http://ocsp.google.com"},
	}
	if matchesHeuristics(cert2) {
		t.Errorf("Expected cert2 to not match heuristics")
	}
}

func TestGroupCertificates(t *testing.T) {
	certMITM := &x509.Certificate{
		IsCA: true,
		Subject: pkix.Name{
			Organization: []string{"Zscaler Inc"},
		},
		Issuer: pkix.Name{
			Organization: []string{"Zscaler Inc"},
		},
	}
	certOS := &x509.Certificate{
		IsCA: true,
		Subject: pkix.Name{
			Organization: []string{"Google Trust Services LLC"},
		},
		Issuer: pkix.Name{
			Organization: []string{"Google Trust Services LLC"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(15, 0, 0),
		CRLDistributionPoints: []string{"http://crl.google.com"},
		OCSPServer:             []string{"http://ocsp.google.com"},
	}
	certDefault := &x509.Certificate{
		IsCA: true,
		Subject: pkix.Name{
			Organization: []string{"Some CA Org"},
		},
		Issuer: pkix.Name{
			Organization: []string{"Some CA Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(15, 0, 0),
		CRLDistributionPoints: []string{"http://crl.someca.org"},
		OCSPServer:             []string{"http://ocsp.someca.org"},
	}

	certs := []*x509.Certificate{certMITM, certOS, certDefault}
	profiles := GroupCertificates(certs)

	// We expect 3 profiles: "Zscaler Inc Proxy" (MITM), "Google Trust Services LLC Root CA" (OS Vendor), "System Default" (Default)
	if len(profiles) != 3 {
		t.Fatalf("Expected 3 profiles, got %d", len(profiles))
	}

	if profiles[0].Name != "Zscaler Inc Proxy" || !profiles[0].IsMITM {
		t.Errorf("Expected first profile to be Zscaler Inc Proxy, got %s", profiles[0].Name)
	}
	if profiles[1].Name != "Google Trust Services LLC Root CA" || profiles[1].IsMITM {
		t.Errorf("Expected second profile to be Google Trust Services LLC Root CA, got %s", profiles[1].Name)
	}
	if profiles[2].Name != "System Default" || profiles[2].IsMITM {
		t.Errorf("Expected third profile to be System Default, got %s", profiles[2].Name)
	}
}

func TestJSONSerialization(t *testing.T) {
	// Mock a certificate
	cert := &x509.Certificate{
		Raw: []byte("mock_cert_raw_bytes"),
		Subject: pkix.Name{
			CommonName: "Mock Test CA",
		},
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	jsonProfile := JSONProfile{
		Name:        "Test Profile",
		Description: "test desc",
		IsMITM:      true,
		Certs:       []string{string(pemBlock)},
	}

	data := JSONData{
		Version:   1,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Profiles:  []JSONProfile{jsonProfile},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	var decoded JSONData
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if decoded.Version != 1 {
		t.Errorf("Expected version 1, got %d", decoded.Version)
	}
	if len(decoded.Profiles) != 1 {
		t.Fatalf("Expected 1 profile, got %d", len(decoded.Profiles))
	}
	if decoded.Profiles[0].Name != "Test Profile" {
		t.Errorf("Expected profile name 'Test Profile', got '%s'", decoded.Profiles[0].Name)
	}

	// Verify certificate reconstruction
	pemStr := decoded.Profiles[0].Certs[0]
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode PEM block")
	}
	if string(block.Bytes) != "mock_cert_raw_bytes" {
		t.Errorf("Decoded certificate bytes do not match original")
	}
}

// ── Overlay tests ─────────────────────────────────────────────────────────────

func TestStripJSONC(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no comments",
			input: `{"a":1}`,
			want:  `{"a":1}`,
		},
		{
			name:  "line comment",
			input: `{"a":1} // this is a comment`,
			want:  `{"a":1} `,
		},
		{
			name:  "block comment",
			input: `{"a":/* comment */1}`,
			want:  `{"a":1}`,
		},
		{
			name:  "comment inside string is preserved",
			input: `{"url":"https://example.com/path"}`,
			want:  `{"url":"https://example.com/path"}`,
		},
		{
			name:  "escaped quote inside string",
			input: `{"msg":"say \"hi\" // not a comment"}`,
			want:  `{"msg":"say \"hi\" // not a comment"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(stripJSONC([]byte(tc.input)))
			if got != tc.want {
				t.Errorf("stripJSONC(%q)\n  got  %q\n  want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestFindDevcontainerJSON(t *testing.T) {
	root := t.TempDir()

	// Plant config at root/.devcontainer/devcontainer.json
	dcDir := filepath.Join(root, ".devcontainer")
	if err := os.MkdirAll(dcDir, 0755); err != nil {
		t.Fatal(err)
	}
	dcFile := filepath.Join(dcDir, "devcontainer.json")
	if err := os.WriteFile(dcFile, []byte(`{"image":"ubuntu"}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Change into a sub-directory and verify the walk-up finds it.
	subDir := filepath.Join(root, "src", "pkg")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(orig) })
	if err := os.Chdir(subDir); err != nil {
		t.Fatal(err)
	}

	found, err := findDevcontainerJSON()
	if err != nil {
		t.Fatalf("findDevcontainerJSON returned error: %v", err)
	}
	if found != dcFile {
		t.Errorf("got %q, want %q", found, dcFile)
	}
}

func TestBuildOverlayJSON(t *testing.T) {
	original := map[string]json.RawMessage{
		"image":    json.RawMessage(`"ubuntu:22.04"`),
		"features": json.RawMessage(`{"ghcr.io/devcontainers/features/go:1":{}}`),
	}

	featureDir := "/home/user/.certsync/ca-inject"
	out, err := buildOverlayJSON(original, featureDir)
	if err != nil {
		t.Fatalf("buildOverlayJSON error: %v", err)
	}
	result := parseOverlayResult(t, out)

	// Original "image" must survive unchanged.
	if string(result["image"]) != `"ubuntu:22.04"` {
		t.Errorf("image field changed: %s", result["image"])
	}

	// features must contain both the original and our injected key.
	var features map[string]json.RawMessage
	if err := json.Unmarshal(result["features"], &features); err != nil {
		t.Fatalf("cannot parse features: %v", err)
	}
	if _, ok := features["ghcr.io/devcontainers/features/go:1"]; !ok {
		t.Error("original feature was dropped")
	}
	if _, ok := features[featureDir]; !ok {
		t.Errorf("certsync feature not injected (key %q missing)", featureDir)
	}
}


// parseOverlayResult strips the leading JSONC comment and unmarshals the body.
func parseOverlayResult(t *testing.T, out []byte) map[string]json.RawMessage {
	t.Helper()
	raw := string(out)
	start := 0
	for i, ch := range raw {
		if ch == '{' {
			start = i
			break
		}
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw[start:]), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	return result
}

func TestBuildOverlayJSONInstallOrder(t *testing.T) {
	featureDir := "/home/user/.certsync/ca-inject"

	t.Run("prepends when field already exists", func(t *testing.T) {
		original := map[string]json.RawMessage{
			"image":                      json.RawMessage(`"ubuntu"`),
			"overrideFeatureInstallOrder": json.RawMessage(`["ghcr.io/devcontainers/features/go:1"]`),
		}
		out, err := buildOverlayJSON(original, featureDir)
		if err != nil {
			t.Fatalf("buildOverlayJSON error: %v", err)
		}
		result := parseOverlayResult(t, out)

		var order []string
		if err := json.Unmarshal(result["overrideFeatureInstallOrder"], &order); err != nil {
			t.Fatalf("cannot parse overrideFeatureInstallOrder: %v", err)
		}
		if len(order) != 2 {
			t.Fatalf("expected 2 entries, got %d: %v", len(order), order)
		}
		if order[0] != featureDir {
			t.Errorf("certsync should be first, got %q", order[0])
		}
		if order[1] != "ghcr.io/devcontainers/features/go:1" {
			t.Errorf("original entry should be second, got %q", order[1])
		}
	})

	t.Run("creates when field is absent", func(t *testing.T) {
		original := map[string]json.RawMessage{
			"image": json.RawMessage(`"ubuntu"`),
		}
		out, err := buildOverlayJSON(original, featureDir)
		if err != nil {
			t.Fatalf("buildOverlayJSON error: %v", err)
		}
		result := parseOverlayResult(t, out)

		raw, ok := result["overrideFeatureInstallOrder"]
		if !ok {
			t.Fatal("overrideFeatureInstallOrder missing from output — should always be written")
		}
		var order []string
		if err := json.Unmarshal(raw, &order); err != nil {
			t.Fatalf("cannot parse overrideFeatureInstallOrder: %v", err)
		}
		if len(order) != 1 || order[0] != featureDir {
			t.Errorf("expected single-element array [%q], got %v", featureDir, order)
		}
	})
}
