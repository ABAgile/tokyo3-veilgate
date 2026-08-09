// Package intercept manages the narrowly scoped CA used to terminate sandbox
// TLS connections. It is not a workload CA: it issues a persistent HTTPS proxy
// endpoint certificate and short-lived, in-memory DNS leaf certificates for
// approved CONNECT destinations.
package intercept

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	leafLifetime             = 24 * time.Hour
	proxyCertificateLifetime = 825 * 24 * time.Hour
	maxCachedCertificates    = 1024
)

// DefaultProxySANs returns the development names used by the HTTPS proxy
// endpoint certificate.
func DefaultProxySANs() []string {
	return []string{
		"DNS:veilgated-proxy",
		"DNS:veilgated",
		"DNS:localhost",
		"IP:127.0.0.1",
		"IP:::1",
	}
}

type cachedCertificate struct {
	certificate *tls.Certificate
	notAfter    time.Time
}

// Authority signs and caches interception certificates in memory.
type Authority struct {
	certificate *x509.Certificate
	signer      crypto.Signer
	leafKey     *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]cachedCertificate
	now   func() time.Time
}

// Load reads and validates an interception CA certificate and private key.
func Load(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read interception CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read interception CA key: %w", err)
	}
	return Parse(certPEM, keyPEM)
}

// Parse validates PEM-encoded interception CA material.
func Parse(certPEM, keyPEM []byte) (*Authority, error) {
	certBlock, rest := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("interception CA certificate must contain exactly one CERTIFICATE PEM block")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse interception CA certificate: %w", err)
	}
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("interception certificate is not permitted to sign certificates")
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, errors.New("interception CA certificate is not currently valid")
	}

	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("interception CA key must contain exactly one private-key PEM block")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal interception CA public key: %w", err)
	}
	certPublicDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal interception certificate public key: %w", err)
	}
	if !cryptoEqual(publicDER, certPublicDER) {
		return nil, errors.New("interception CA certificate and private key do not match")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate interception leaf key: %w", err)
	}
	return &Authority{
		certificate: certificate,
		signer:      key,
		leafKey:     leafKey,
		cache:       make(map[string]cachedCertificate),
		now:         time.Now,
	}, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, errors.New("interception CA PKCS#8 key cannot sign")
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("parse interception CA private key: unsupported PKCS#8, PKCS#1, or EC key")
}

func cryptoEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

// TLSConfig builds a server config that requires the ClientHello SNI to match
// the approved CONNECT hostname and advertises HTTP/2 and HTTP/1.1 mediation.
func (a *Authority) TLSConfig(host string) (*tls.Config, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	certificate, err := a.certificateFor(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
			if serverName == "" || serverName != host {
				return nil, fmt.Errorf("TLS SNI %q does not match CONNECT host %q", serverName, host)
			}
			return certificate, nil
		},
	}, nil
}

func (a *Authority) certificateFor(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if cached, ok := a.cache[host]; ok && now.Add(5*time.Minute).Before(cached.notAfter) {
		return cached.certificate, nil
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(leafLifetime)
	if a.certificate.NotAfter.Before(notAfter) {
		notAfter = a.certificate.NotAfter
	}
	if !now.Add(5 * time.Minute).Before(notAfter) {
		return nil, errors.New("interception CA expires too soon to issue a leaf certificate")
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &a.leafKey.PublicKey, a.signer)
	if err != nil {
		return nil, fmt.Errorf("sign interception certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse signed interception certificate: %w", err)
	}
	certificate := &tls.Certificate{
		Certificate: [][]byte{der, a.certificate.Raw},
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}
	if len(a.cache) >= maxCachedCertificates {
		for name, cached := range a.cache {
			if !now.Before(cached.notAfter) {
				delete(a.cache, name)
			}
		}
	}
	if len(a.cache) < maxCachedCertificates {
		a.cache[host] = cachedCertificate{certificate: certificate, notAfter: notAfter}
	}
	return certificate, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("generate certificate serial: %w", err)
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// Generate writes a new Ed25519 interception CA certificate and PKCS#8 key.
// Existing paths are never overwritten.
func Generate(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" || certPath == keyPath {
		return errors.New("distinct certificate and key paths are required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate interception CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Veilgate Development Interception CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create interception CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal interception CA key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeExclusive(certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeExclusive(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(certPath)
		return err
	}
	return nil
}

// GenerateProxyCertificate generates an HTTPS proxy endpoint certificate
// signed by the interception CA. The endpoint key is always generated
// separately from the CA key, and existing output files are never overwritten.
func GenerateProxyCertificate(caCertPath, caKeyPath, certPath, keyPath string, sans []string) error {
	if caCertPath == "" || caKeyPath == "" || certPath == "" || keyPath == "" {
		return errors.New("CA and proxy certificate and key paths are required")
	}
	if caCertPath == caKeyPath || certPath == keyPath {
		return errors.New("certificate and key paths must be distinct")
	}
	if certPath == caCertPath || certPath == caKeyPath || keyPath == caCertPath || keyPath == caKeyPath {
		return errors.New("proxy certificate paths must differ from CA paths")
	}
	dnsNames, ipAddresses, err := parseProxySANs(sans)
	if err != nil {
		return err
	}
	authority, err := Load(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load signing CA: %w", err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate proxy certificate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	notBefore := now.Add(-5 * time.Minute)
	if authority.certificate.NotBefore.After(notBefore) {
		notBefore = authority.certificate.NotBefore
	}
	notAfter := now.Add(proxyCertificateLifetime)
	if authority.certificate.NotAfter.Before(notAfter) {
		notAfter = authority.certificate.NotAfter
	}
	if !notBefore.Add(5 * time.Minute).Before(notAfter) {
		return errors.New("interception CA expires too soon to issue a proxy certificate")
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "veilgated-proxy"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, &privateKey.PublicKey, authority.signer)
	if err != nil {
		return fmt.Errorf("create proxy certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal proxy certificate key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeExclusive(certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeExclusive(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(certPath)
		return err
	}
	return nil
}

func parseProxySANs(values []string) ([]string, []net.IP, error) {
	var dnsNames []string
	var ipAddresses []net.IP
	for _, value := range values {
		for raw := range strings.SplitSeq(value, ",") {
			entry := strings.TrimSpace(raw)
			if entry == "" {
				continue
			}
			switch {
			case strings.HasPrefix(entry, "DNS:"):
				name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(entry, "DNS:")), "."))
				if !validProxyDNSName(name) {
					return nil, nil, fmt.Errorf("invalid proxy DNS SAN %q", name)
				}
				dnsNames = append(dnsNames, name)
			case strings.HasPrefix(entry, "IP:"):
				ip := net.ParseIP(strings.TrimSpace(strings.TrimPrefix(entry, "IP:")))
				if ip == nil {
					return nil, nil, fmt.Errorf("invalid proxy IP SAN %q", entry)
				}
				if ipv4 := ip.To4(); ipv4 != nil {
					ip = ipv4
				}
				ipAddresses = append(ipAddresses, ip)
			default:
				return nil, nil, fmt.Errorf("proxy SAN %q must use DNS: or IP: prefix", entry)
			}
		}
	}
	if len(dnsNames) == 0 && len(ipAddresses) == 0 {
		return nil, nil, errors.New("at least one proxy DNS or IP SAN is required")
	}
	return dnsNames, ipAddresses, nil
}

func validProxyDNSName(name string) bool {
	if name == "" || len(name) > 253 || strings.Contains(name, "*") {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create interception CA directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
