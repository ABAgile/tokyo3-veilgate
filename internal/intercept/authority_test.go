package intercept

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateLoadAndIssue(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("key mode = %o", got)
	}
	authority, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := authority.TLSConfig("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append generated root")
	}
	if _, err := certificate.Leaf.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: roots}); err != nil {
		t.Fatalf("verify issued leaf: %v", err)
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); err == nil {
		t.Fatal("mismatched SNI accepted")
	}
	if err := Generate(certPath, keyPath); err == nil {
		t.Fatal("Generate overwrote existing material")
	}
}

func TestTLSConfigRenewsLeafAtHandshakeTime(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	authority, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	authority.now = func() time.Time { return clock }
	cfg, err := authority.TLSConfig("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	first, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(leafLifetime - 4*time.Minute)
	second, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("TLS config continued serving the stale leaf")
	}
	if !second.Leaf.NotAfter.After(clock.Add(leafLifetime - time.Minute)) {
		t.Fatalf("renewed leaf expires at %v, too soon for clock %v", second.Leaf.NotAfter, clock)
	}
}

func TestGenerateProxyCertificate(t *testing.T) {
	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	proxyCertPath := filepath.Join(dir, "proxy.crt")
	proxyKeyPath := filepath.Join(dir, "proxy.key")
	if err := Generate(caCertPath, caKeyPath); err != nil {
		t.Fatal(err)
	}
	if err := GenerateProxyCertificate(caCertPath, caKeyPath, proxyCertPath, proxyKeyPath, []string{
		"DNS:proxy.example",
		"DNS:localhost",
		"IP:127.0.0.1",
		"IP:::1",
	}); err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(proxyKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("proxy key mode = %o", got)
	}
	certPEM, err := os.ReadFile(proxyCertPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(proxyKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if certificate.IsCA {
		t.Fatal("proxy certificate is a CA")
	}
	if got, want := certificate.DNSNames, []string{"proxy.example", "localhost"}; !equalStrings(got, want) {
		t.Fatalf("proxy DNS SANs = %v, want %v", got, want)
	}
	if got, want := len(certificate.IPAddresses), 2; got != want {
		t.Fatalf("proxy IP SAN count = %d, want %d", got, want)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(mustReadFile(t, caCertPath)) {
		t.Fatal("append generated root")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{DNSName: "proxy.example", Roots: roots}); err != nil {
		t.Fatalf("verify proxy certificate: %v", err)
	}
	authority, err := Load(caCertPath, caKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	proxySigner, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("proxy key is not a signer")
	}
	proxyPublicDER, err := x509.MarshalPKIXPublicKey(proxySigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	caPublicDER, err := x509.MarshalPKIXPublicKey(authority.signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(proxyPublicDER, caPublicDER) {
		t.Fatal("proxy key reuses the CA key")
	}
	beforeCert, beforeKey := append([]byte(nil), certPEM...), append([]byte(nil), keyPEM...)
	if err := GenerateProxyCertificate(caCertPath, caKeyPath, proxyCertPath, proxyKeyPath, []string{"DNS:proxy.example"}); err == nil {
		t.Fatal("GenerateProxyCertificate overwrote existing material")
	}
	afterCert, err := os.ReadFile(proxyCertPath)
	if err != nil {
		t.Fatal(err)
	}
	afterKey, err := os.ReadFile(proxyKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterCert, beforeCert) || !bytes.Equal(afterKey, beforeKey) {
		t.Fatal("existing proxy material changed")
	}
}

func TestIssuedLeavesUseDistinctKeys(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	authority, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.certificateFor("one.example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.certificateFor("two.example")
	if err != nil {
		t.Fatal(err)
	}
	firstSigner, ok := first.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("first leaf key is not a signer")
	}
	secondSigner, ok := second.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("second leaf key is not a signer")
	}
	firstDER, err := x509.MarshalPKIXPublicKey(firstSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	secondDER, err := x509.MarshalPKIXPublicKey(secondSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstDER, secondDER) {
		t.Fatal("different interception leaves share a private key")
	}
	cached, err := authority.certificateFor("one.example")
	if err != nil {
		t.Fatal(err)
	}
	cachedSigner, ok := cached.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatal("cached leaf key is not a signer")
	}
	cachedDER, err := x509.MarshalPKIXPublicKey(cachedSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstDER, cachedDER) {
		t.Fatal("cached interception leaf was re-keyed")
	}
}

func TestLeafCacheEvictsLeastRecentlyUsed(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	authority, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.certificateFor("oldest.example"); err != nil {
		t.Fatal(err)
	}
	cached := authority.cache["oldest.example"]
	cached.lastUsed = time.Unix(0, 0)
	authority.cache["oldest.example"] = cached
	for index := 1; index < maxCachedCertificates; index++ {
		authority.cache[fmt.Sprintf("cached-%04d.example", index)] = cachedCertificate{
			certificate: cached.certificate,
			notAfter:    time.Now().Add(time.Hour),
			lastUsed:    time.Unix(0, int64(index)),
		}
	}
	if len(authority.cache) != maxCachedCertificates {
		t.Fatalf("cache size = %d, want %d", len(authority.cache), maxCachedCertificates)
	}
	if _, err := authority.certificateFor("new.example"); err != nil {
		t.Fatal(err)
	}
	if _, ok := authority.cache["oldest.example"]; ok {
		t.Fatal("least-recently-used leaf was not evicted")
	}
	if _, ok := authority.cache["new.example"]; !ok {
		t.Fatal("new leaf was not cached")
	}
	if len(authority.cache) != maxCachedCertificates {
		t.Fatalf("cache size after eviction = %d, want %d", len(authority.cache), maxCachedCertificates)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseRejectsMismatchedKey(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	if err := Generate(filepath.Join(first, "ca.crt"), filepath.Join(first, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if err := Generate(filepath.Join(second, "ca.crt"), filepath.Join(second, "ca.key")); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(filepath.Join(first, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(second, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(certPEM, keyPEM); err == nil {
		t.Fatal("Parse accepted a mismatched private key")
	}
}
