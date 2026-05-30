//go:build linux

package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
)

// enableAnsi is a no-op on Linux.
func enableAnsi() {}

// GetHostCertificates scans standard Linux directories for CA certificates.
func GetHostCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	dirs := []string{"/etc/ssl/certs", "/etc/pki/tls/certs"}

	for _, dir := range dirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for len(data) > 0 {
				var block *pem.Block
				block, data = pem.Decode(data)
				if block == nil {
					break
				}
				if block.Type == "CERTIFICATE" {
					cert, err := x509.ParseCertificate(block.Bytes)
					if err == nil && cert.IsCA {
						certs = append(certs, cert)
					}
				}
			}
			return nil
		})
	}
	return certs, nil
}
