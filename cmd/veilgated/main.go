// Command veilgated is a secret-aware egress gateway for agent sandboxes.
//
// Veilgated authenticates proxy clients with lifecycle-scoped bearer
// credentials, enforces per-client hostname and port allowlists, rejects
// private and special-use destination addresses, forwards HTTP, optionally
// intercepts HTTPS CONNECT traffic for HTTP/2 or HTTP/1.1 mediation, and serves a
// bounded sanitized traffic console. Intercepted HTTP/1.1 and uncompressed
// WebSocket text traffic can be examined without retaining configured values.
//
// Configuration files are looked up under /etc/veilgate by default and
// durable runtime state is kept under /var/lib/veilgate. Every path can still
// be overridden for development or a managed deployment.
//
// Required material (the default paths are used when the variables are unset):
//
//	VEILGATED_CLIENTS_FILE  JSON client policy path (default "/etc/veilgate/clients.json").
//	VEILGATED_PROXY_CERT    HTTPS proxy server certificate PEM (default "/etc/veilgate/proxy.crt").
//	VEILGATED_PROXY_KEY     Matching HTTPS proxy server private key PEM (default "/etc/veilgate/proxy.key").
//
// Optional environment variables:
//
//	VEILGATED_ADDR              HTTPS proxy listen address (default "127.0.0.1:8080").
//	VEILGATED_CONSOLE_ADDR      HTTPS console listen address (default "127.0.0.1:8081").
//	VEILGATED_CONSOLE_CERT      HTTPS console certificate PEM (default "/etc/veilgate/console.crt").
//	VEILGATED_CONSOLE_KEY       Matching HTTPS console private key PEM (default "/etc/veilgate/console.key").
//	VEILGATED_CONSOLE_USERNAME  HTTP Basic username for the console. Must be set
//	                            together with VEILGATED_CONSOLE_PASSWORD when
//	                            VEILGATED_CONSOLE_ADDR is not loopback.
//	VEILGATED_CONSOLE_PASSWORD  HTTP Basic password for the console.
//	VEILGATED_FLOW_RETENTION    Number of flows retained (default 1000).
//	VEILGATED_DATABASE_URL      sqlite:<path> durable flow store (default
//	                            "sqlite:/var/lib/veilgate/flows.db").
//	VEILGATED_SECRETS_FILE      Optional JSON static secret-broker definitions;
//	                            defaults to "/etc/veilgate/secrets.json" when
//	                            present and non-empty.
//	VEILGATED_OAUTH_FILE        Optional OAuth broker policy; defaults to
//	                            "/etc/veilgate/oauth.json" when present and
//	                            non-empty.
//	VEILGATED_AUTH_FILE         Plaintext OAuth token state path (default
//	                            "/var/lib/veilgate/auth.json"). Keep outside sandbox mounts.
//	VEILGATED_DIAL_TIMEOUT      Upstream connection timeout (default "10s").
//	VEILGATED_SESSION_IDLE_TIMEOUT Close sessions after this period without I/O
//	                            (default "5m").
//	VEILGATED_SESSION_MAX_DURATION Maximum lifetime of one proxy request/session
//	                            (default "30m").
//	VEILGATED_UPSTREAM_RESPONSE_HEADER_TIMEOUT Maximum wait for upstream response
//	                            headers (default "60s").
//	VEILGATED_CAPTURE_LIMIT_BYTES Maximum retained content per capture section
//	                            (default 1048576; maximum 4194304).
//	VEILGATED_MEDIATION_LIMIT_BYTES Maximum decoded request, response, or WebSocket
//	                            message size (default 4194304; maximum 67108864).
//	VEILGATED_RECORD_QUEUE_CAPACITY Number of completed flows buffered for recording
//	                            (default 256; minimum 1).
//	VEILGATED_RECORD_WORKERS    Number of concurrent flow-recording workers
//	                            (default 4; minimum 1).
//	VEILGATED_INTERCEPT_CA_CERT Interception CA certificate PEM; when unset, the
//	                            default "/etc/veilgate/intercept-ca.crt" is used
//	                            when that file or its key is present.
//	VEILGATED_INTERCEPT_CA_KEY  Matching interception CA private key PEM (default
//	                            "/etc/veilgate/intercept-ca.key" when present).
//	VEILGATED_DEBUG_ADDR        Optional plaintext diagnostics address. Never expose
//	                            publicly; it serves unauthenticated profiling.
//	VEILGATED_NATS_URL          Optional NATS URL for durable audit publication.
//	VEILGATED_NATS_CERT/KEY/CA  Optional NATS mTLS material, falling back to the
//	                            matching VEILGATED_WORKLOAD_CERT/KEY/CA variables.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/abagile/tokyo3-base/cli"
	"github.com/abagile/tokyo3-base/envutil"
	"github.com/abagile/tokyo3-base/guard"
	"github.com/abagile/tokyo3-base/run"
	"github.com/abagile/tokyo3-base/version"
	"github.com/spf13/cobra"

	"github.com/abagile/veilgate/internal/audit"
	"github.com/abagile/veilgate/internal/config"
	"github.com/abagile/veilgate/internal/console"
	"github.com/abagile/veilgate/internal/flow"
	"github.com/abagile/veilgate/internal/intercept"
	"github.com/abagile/veilgate/internal/oauth"
	"github.com/abagile/veilgate/internal/proxy"
	"github.com/abagile/veilgate/internal/secret"
)

const (
	appName = "veilgated"

	defaultConfigDir = "/etc/veilgate"
	defaultDataDir   = "/var/lib/veilgate"

	defaultClientsFile   = defaultConfigDir + "/clients.json"
	defaultSecretsFile   = defaultConfigDir + "/secrets.json"
	defaultOAuthFile     = defaultConfigDir + "/oauth.json"
	defaultInterceptCert = defaultConfigDir + "/intercept-ca.crt"
	defaultInterceptKey  = defaultConfigDir + "/intercept-ca.key"
	defaultProxyCert     = defaultConfigDir + "/proxy.crt"
	defaultProxyKey      = defaultConfigDir + "/proxy.key"
	defaultConsoleCert   = defaultConfigDir + "/console.crt"
	defaultConsoleKey    = defaultConfigDir + "/console.key"
	defaultAuthFile      = defaultDataDir + "/auth.json"
	defaultDatabaseURL   = "sqlite:" + defaultDataDir + "/flows.db"
)

// Version is overridden at build time with -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{Use: appName, Short: "secret-aware agent sandbox egress gateway"}
	root.AddCommand(serveCmd(), versionCmd(), caCmd())
	return root
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the egress proxy and traffic console",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context())
		},
	}
}

func runServe(ctx context.Context) error {
	rt := cli.App{Name: appName, EnvPrefix: "VEILGATED"}.Setup(ctx)
	defer rt.Shutdown()

	policyPath := envutil.Or("VEILGATED_CLIENTS_FILE", defaultClientsFile)
	policy, err := config.Load(policyPath)
	if err != nil {
		return fmt.Errorf("load clients: %w", err)
	}
	retention, err := envutil.Int("VEILGATED_FLOW_RETENTION")
	if err != nil {
		return err
	}
	if retention == 0 {
		retention = 1000
	}
	if retention < 1 || retention > 100_000 {
		return errors.New("VEILGATED_FLOW_RETENTION must be between 1 and 100000")
	}
	dialTimeout, err := envutil.Duration("VEILGATED_DIAL_TIMEOUT")
	if err != nil {
		return err
	}
	if dialTimeout == 0 {
		dialTimeout = 10 * time.Second
	}
	if dialTimeout < time.Millisecond {
		return errors.New("VEILGATED_DIAL_TIMEOUT must be at least 1ms")
	}
	sessionIdleTimeout, err := envutil.Duration("VEILGATED_SESSION_IDLE_TIMEOUT")
	if err != nil {
		return err
	}
	if sessionIdleTimeout == 0 {
		sessionIdleTimeout = 5 * time.Minute
	}
	if sessionIdleTimeout < time.Second || sessionIdleTimeout > 24*time.Hour {
		return errors.New("VEILGATED_SESSION_IDLE_TIMEOUT must be between 1s and 24h")
	}
	sessionMaxDuration, err := envutil.Duration("VEILGATED_SESSION_MAX_DURATION")
	if err != nil {
		return err
	}
	if sessionMaxDuration == 0 {
		sessionMaxDuration = 30 * time.Minute
	}
	if sessionMaxDuration < sessionIdleTimeout || sessionMaxDuration > 7*24*time.Hour {
		return errors.New("VEILGATED_SESSION_MAX_DURATION must be at least the idle timeout and at most 168h")
	}
	responseHeaderTimeout, err := envutil.Duration("VEILGATED_UPSTREAM_RESPONSE_HEADER_TIMEOUT")
	if err != nil {
		return err
	}
	if responseHeaderTimeout == 0 {
		responseHeaderTimeout = 60 * time.Second
	}
	if responseHeaderTimeout < time.Second || responseHeaderTimeout > 10*time.Minute {
		return errors.New("VEILGATED_UPSTREAM_RESPONSE_HEADER_TIMEOUT must be between 1s and 10m")
	}
	captureLimit, err := envutil.Int("VEILGATED_CAPTURE_LIMIT_BYTES")
	if err != nil {
		return err
	}
	if captureLimit == 0 {
		captureLimit = 1 << 20
	}
	if captureLimit < 1024 || captureLimit > 4<<20 {
		return errors.New("VEILGATED_CAPTURE_LIMIT_BYTES must be between 1024 and 4194304")
	}
	mediationLimit, err := envutil.Int("VEILGATED_MEDIATION_LIMIT_BYTES")
	if err != nil {
		return err
	}
	if mediationLimit == 0 {
		mediationLimit = 4 << 20
	}
	if mediationLimit < captureLimit || mediationLimit > 64<<20 {
		return errors.New("VEILGATED_MEDIATION_LIMIT_BYTES must be at least the capture limit and at most 67108864")
	}
	recordQueueCapacity, err := envutil.Int("VEILGATED_RECORD_QUEUE_CAPACITY")
	if err != nil {
		return err
	}
	if recordQueueCapacity == 0 {
		recordQueueCapacity = 256
	}
	if recordQueueCapacity < 1 {
		return errors.New("VEILGATED_RECORD_QUEUE_CAPACITY must be at least 1")
	}
	recordWorkers, err := envutil.Int("VEILGATED_RECORD_WORKERS")
	if err != nil {
		return err
	}
	if recordWorkers == 0 {
		recordWorkers = 4
	}
	if recordWorkers < 1 {
		return errors.New("VEILGATED_RECORD_WORKERS must be at least 1")
	}

	consoleAddr := envutil.Or("VEILGATED_CONSOLE_ADDR", "127.0.0.1:8081")
	consoleUser := os.Getenv("VEILGATED_CONSOLE_USERNAME")
	consolePassword := os.Getenv("VEILGATED_CONSOLE_PASSWORD")
	if err := validateConsoleAuth(consoleAddr, consoleUser, consolePassword); err != nil {
		return err
	}

	proxyCertPath := envutil.Or("VEILGATED_PROXY_CERT", defaultProxyCert)
	proxyKeyPath := envutil.Or("VEILGATED_PROXY_KEY", defaultProxyKey)
	if !fileExists(proxyCertPath) || !fileExists(proxyKeyPath) {
		return fmt.Errorf("VEILGATED_PROXY_CERT and VEILGATED_PROXY_KEY are required; provide the certificate and key or create the defaults at %s and %s", defaultProxyCert, defaultProxyKey)
	}
	proxyCertificate, err := tls.LoadX509KeyPair(proxyCertPath, proxyKeyPath)
	if err != nil {
		return fmt.Errorf("load HTTPS proxy certificate: %w", err)
	}
	proxyTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{proxyCertificate},
		NextProtos:   []string{"http/1.1"},
	}

	auditSink, err := cli.AuditSink[audit.Entry](rt, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
	defer guard.Close(auditSink)

	var interceptionAuthority *intercept.Authority
	interceptCert := os.Getenv("VEILGATED_INTERCEPT_CA_CERT")
	interceptKey := os.Getenv("VEILGATED_INTERCEPT_CA_KEY")
	if interceptCert == "" && interceptKey == "" && (fileExists(defaultInterceptCert) || fileExists(defaultInterceptKey)) {
		interceptCert = defaultInterceptCert
		interceptKey = defaultInterceptKey
	}
	if (interceptCert == "") != (interceptKey == "") {
		return errors.New("VEILGATED_INTERCEPT_CA_CERT and VEILGATED_INTERCEPT_CA_KEY must be set together")
	}
	if interceptCert != "" {
		interceptionAuthority, err = intercept.Load(interceptCert, interceptKey)
		if err != nil {
			return fmt.Errorf("load interception CA: %w", err)
		}
		rt.Log.Info("HTTPS interception enabled", "ca_cert", interceptCert)
	} else {
		rt.Log.Warn("HTTPS interception disabled; CONNECT traffic remains opaque")
	}
	var secretBroker *secret.Broker
	if secretsPath := optionalPolicyFile("VEILGATED_SECRETS_FILE", defaultSecretsFile, "secrets"); secretsPath != "" {
		if interceptionAuthority == nil {
			return errors.New("VEILGATED_SECRETS_FILE requires TLS interception CA material")
		}
		secretBroker, err = secret.Load(secretsPath)
		if err != nil {
			return fmt.Errorf("load secret broker: %w", err)
		}
		rt.Log.Info("secret broker enabled", "config", secretsPath)
	}

	var oauthBroker *oauth.Broker
	if oauthPath := optionalPolicyFile("VEILGATED_OAUTH_FILE", defaultOAuthFile, "brokers"); oauthPath != "" {
		if interceptionAuthority == nil {
			return errors.New("VEILGATED_OAUTH_FILE requires TLS interception CA material")
		}
		authPath := envutil.Or("VEILGATED_AUTH_FILE", defaultAuthFile)
		oauthBroker, err = oauth.Load(oauthPath, authPath)
		if err != nil {
			return fmt.Errorf("load OAuth broker: %w", err)
		}
		rt.Log.Warn("OAuth broker enabled with plaintext auth state", "config", oauthPath, "auth_state", authPath, "encryption", "disabled")
	}
	broker := proxy.CombineBrokers(secretBroker, oauthBroker)
	var interceptor proxy.Interceptor
	if interceptionAuthority != nil {
		interceptor = interceptionAuthority
	}
	var oauthHandler proxy.OAuthBroker
	if oauthBroker != nil {
		oauthHandler = oauthBroker
	}

	databaseURL := envutil.Or("VEILGATED_DATABASE_URL", defaultDatabaseURL)
	store, err := flow.Open(databaseURL, retention)
	if err != nil {
		return fmt.Errorf("open flow store: %w", err)
	}
	defer guard.Close(store)
	rt.Log.Info("durable flow store enabled", "database", databaseURL)
	proxyHandler := &proxy.Handler{
		Policy:                        policy,
		Resolver:                      proxy.PublicResolver{},
		Store:                         store,
		Log:                           rt.Log,
		Interceptor:                   interceptor,
		Secrets:                       broker,
		OAuth:                         oauthHandler,
		DialTimeout:                   dialTimeout,
		SessionIdleTimeout:            sessionIdleTimeout,
		SessionMaxDuration:            sessionMaxDuration,
		UpstreamResponseHeaderTimeout: responseHeaderTimeout,
		CaptureLimit:                  int64(captureLimit),
		MediationLimit:                int64(mediationLimit),
		RecordQueueCapacity:           recordQueueCapacity,
		RecordWorkers:                 recordWorkers,
		Record: func(ctx context.Context, item flow.Flow) {
			entry := audit.Entry{
				Time: item.StartedAt, FlowID: item.ID, SessionID: item.SessionID, Client: item.Client,
				Method: item.Method, Host: item.Host, Port: item.Port,
				Path: item.Path, Mode: item.Mode, DestinationIP: item.DestinationIP,
				Decision: item.Decision,
				Reason:   item.Reason, Status: item.Status, SecretNames: item.SecretNames,
				ResponseSecretNames: item.ResponseSecretNames,
			}
			if err := auditSink.Append(ctx, entry); err != nil {
				rt.Log.Error("publish flow audit event", "flow_id", item.ID, "err", err)
			}
		},
	}
	defer guard.Close(proxyHandler)
	consoleHandler, err := console.Handler(store, consoleUser, consolePassword)
	if err != nil {
		return err
	}
	consoleCertPath := envutil.Or("VEILGATED_CONSOLE_CERT", defaultConsoleCert)
	consoleKeyPath := envutil.Or("VEILGATED_CONSOLE_KEY", defaultConsoleKey)
	consoleCertificate, err := tls.LoadX509KeyPair(consoleCertPath, consoleKeyPath)
	if err != nil {
		return fmt.Errorf("load HTTPS console certificate: %w", err)
	}
	consoleTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{consoleCertificate},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	proxyAddr := envutil.Or("VEILGATED_ADDR", "127.0.0.1:8080")
	proxyServer := &http.Server{
		Addr:              proxyAddr,
		Handler:           proxyHandler,
		TLSConfig:         proxyTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       sessionIdleTimeout,
		WriteTimeout:      sessionMaxDuration,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	consoleServer := &http.Server{
		Addr:              consoleAddr,
		Handler:           consoleHandler,
		TLSConfig:         consoleTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if consoleUser == "" {
		rt.Log.Warn("console running unauthenticated", "console_addr", consoleAddr, "reason", "loopback listen address")
	}
	rt.Log.Info("veilgate starting", "proxy_addr", proxyAddr, "console_addr", consoleAddr, "clients", len(policy.Clients), "observation_clients", observationClientCount(policy))
	return run.Group(rt.Ctx,
		run.HTTPServer(proxyServer, 10*time.Second, true),
		run.HTTPServer(consoleServer, 10*time.Second, true),
	)
}

func optionalPolicyFile(envName, fallback, collection string) string {
	path := os.Getenv(envName)
	if path == "" {
		path = fallback
	}
	if !fileExists(path) {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// Keep the path so the loader returns the useful permission/read error.
		return path
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return ""
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		// Non-empty malformed input remains a startup error.
		return path
	}
	if len(document) == 0 {
		return ""
	}
	if len(document) != 1 {
		return path
	}
	entries, ok := document[collection]
	if !ok {
		return path
	}
	var values []json.RawMessage
	if err := json.Unmarshal(entries, &values); err == nil && len(values) == 0 {
		return ""
	}
	return path
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func validateConsoleAuth(addr, username, password string) error {
	if (username == "") != (password == "") {
		return errors.New("VEILGATED_CONSOLE_USERNAME and VEILGATED_CONSOLE_PASSWORD must be set together")
	}
	if username == "" && !isLoopbackConsoleAddr(addr) {
		return fmt.Errorf("VEILGATED_CONSOLE_USERNAME and VEILGATED_CONSOLE_PASSWORD are required when VEILGATED_CONSOLE_ADDR %q is not loopback", addr)
	}
	return nil
}

func isLoopbackConsoleAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
	if normalizedHost == "localhost" || strings.HasSuffix(normalizedHost, ".localhost") {
		return true
	}
	parsed, err := netip.ParseAddr(host)
	return err == nil && parsed.Unmap().IsLoopback()
}

func observationClientCount(policy *config.File) int {
	count := 0
	for _, client := range policy.Clients {
		if client.ObserveAllPublicHosts {
			count++
		}
	}
	return count
}

func caCmd() *cobra.Command {
	ca := &cobra.Command{Use: "ca", Short: "Manage the local TLS interception CA"}
	var certPath, keyPath string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a development interception CA without overwriting files",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := intercept.Generate(certPath, keyPath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote interception CA certificate to %s\nwrote interception CA key to %s\n", certPath, keyPath)
			return nil
		},
	}
	initCmd.Flags().StringVar(&certPath, "cert", defaultInterceptCert, "certificate output path")
	initCmd.Flags().StringVar(&keyPath, "key", defaultInterceptKey, "private-key output path")

	var caCertPath, caKeyPath, proxyCertPath, proxyKeyPath string
	var proxySANs []string
	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Generate an HTTPS proxy certificate signed by the interception CA",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := intercept.GenerateProxyCertificate(caCertPath, caKeyPath, proxyCertPath, proxyKeyPath, proxySANs); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote proxy certificate to %s\nwrote proxy key to %s\n", proxyCertPath, proxyKeyPath)
			return nil
		},
	}
	signCmd.Flags().StringVar(&caCertPath, "ca-cert", defaultInterceptCert, "interception CA certificate path")
	signCmd.Flags().StringVar(&caKeyPath, "ca-key", defaultInterceptKey, "interception CA private-key path")
	signCmd.Flags().StringVar(&proxyCertPath, "cert", defaultProxyCert, "proxy certificate output path")
	signCmd.Flags().StringVar(&proxyKeyPath, "key", defaultProxyKey, "proxy private-key output path")
	signCmd.Flags().StringSliceVar(&proxySANs, "san", intercept.DefaultProxySANs(), "proxy certificate SANs as DNS:name or IP:address values")

	ca.AddCommand(initCmd, signCmd)
	return ca
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the veilgated version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Resolve(Version))
		},
	}
}
