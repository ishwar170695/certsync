//go:build windows

package main

import (
	"crypto/x509"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enableAnsi enables Virtual Terminal Processing on Windows.
func enableAnsi() {
	stdout := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(stdout, &mode); err == nil {
		mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
		windows.SetConsoleMode(stdout, mode)
	}
}

// GetHostCertificates retrieves CA certificates from the Windows stores.
func GetHostCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	stores := []string{"ROOT", "CA", "MY"}

	for _, storeName := range stores {
		store, err := windows.CertOpenSystemStore(0, windows.StringToUTF16Ptr(storeName))
		if err != nil {
			continue
		}
		var prev *windows.CertContext
		for {
			next, err := windows.CertEnumCertificatesInStore(store, prev)
			if err != nil || next == nil {
				break
			}
			prev = next

			// Copy DER bytes from Windows-managed memory context to avoid invalidation in subsequent loop calls
			der := make([]byte, prev.Length)
			copy(der, unsafe.Slice(prev.EncodedCert, prev.Length))

			cert, err := x509.ParseCertificate(der)
			if err == nil && cert.IsCA {
				certs = append(certs, cert)
			}
		}
		windows.CertCloseStore(store, 0)
	}
	return certs, nil
}
