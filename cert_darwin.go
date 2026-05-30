//go:build darwin

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os/exec"
)

// enableAnsi is a no-op on macOS.
func enableAnsi() {}

// GetHostCertificates retrieves CA certificates from macOS keychains.
func GetHostCertificates() ([]*x509.Certificate, error) {
	keychains := []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}
	var certs []*x509.Certificate

	for _, kc := range keychains {
		cmd := exec.Command("security", "find-certificate", "-a", "-p", kc)
		output, err := cmd.Output()
		if err != nil {
			continue
		}
		data := output
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
	}
	return certs, nil
}
