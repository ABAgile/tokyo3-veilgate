// Command veilgated is a secret-aware egress gateway for agent sandboxes.
//
// Veilgated authenticates proxy clients with lifecycle-scoped bearer
// credentials, enforces per-client hostname and port allowlists, rejects
// private and special-use destination addresses, forwards HTTP, optionally
// intercepts HTTPS CONNECT traffic for HTTP/2 or HTTP/1.1 mediation, and serves a
// bounded sanitized traffic console. Intercepted HTTP/1.1 and uncompressed
// WebSocket text traffic can be examined without retaining configured values.
//
// Required environment variables:
//
//	VEILGATED_CLIENTS_FILE  JSON client policy path. See config/clients.example.json.
//
// Optional environment variables:
//
//	VEILGATED_ADDR              HTTPS proxy listen address (default "127.0.0.1:8080").
//	VEILGATED_PROXY_CERT        HTTPS proxy server certificate PEM. Required.
//	VEILGATED_PROXY_KEY         Matching HTTPS proxy server private key PEM. Required.
//	VEILGATED_CONSOLE_ADDR      HTTPS console listen address (default "127.0.0.1:8081").
//	VEILGATED_CONSOLE_CERT      HTTPS console certificate PEM (default "config/console.crt").
//	VEILGATED_CONSOLE_KEY       Matching HTTPS console private key PEM (default "config/console.key").
//	VEILGATED_CONSOLE_USERNAME  HTTP Basic username for the console. Must be set
//	                            together with VEILGATED_CONSOLE_PASSWORD.
//	VEILGATED_CONSOLE_PASSWORD  HTTP Basic password for the console.
//	VEILGATED_FLOW_RETENTION    Number of flows retained (default 1000).
//	VEILGATED_DATABASE_URL      Optional sqlite:<path> durable flow store. Empty uses
//	                            bounded in-memory retention.
//	VEILGATED_SECRETS_FILE      Optional JSON static secret-broker definitions. Requires
//	                            TLS interception and all referenced host env values.
//	VEILGATED_OAUTH_FILE        Optional OAuth broker policy. Requires TLS interception.
//	VEILGATED_AUTH_FILE         Plaintext OAuth token state path (default
//	                            "/var/lib/veilgate/auth.json"). Keep outside sandbox mounts.
//	VEILGATED_DIAL_TIMEOUT      Upstream connection timeout (default "10s").
//	VEILGATED_SESSION_IDLE_TIMEOUT Close sessions after this period without I/O
//	                            (default "5m").
//	VEILGATED_SESSION_MAX_DURATION Maximum lifetime of one proxy request/session
//	                            (default "30m").
//	VEILGATED_UPSTREAM_RESPONSE_HEADER_TIMEOUT Maximum wait for upstream response
//	                            headers (default "30s").
//	VEILGATED_CAPTURE_LIMIT_BYTES Maximum retained content per capture section
//	                            (default 262144; maximum 4194304).
//	VEILGATED_MEDIATION_LIMIT_BYTES Maximum decoded request, response, or WebSocket
//	                            message size (default 4194304; maximum 67108864).
//	VEILGATED_INTERCEPT_CA_CERT Interception CA certificate PEM. Must be set with
//	                            VEILGATED_INTERCEPT_CA_KEY to enable HTTPS mediation.
//	VEILGATED_INTERCEPT_CA_KEY  Matching interception CA private key PEM. Loaded at
//	                            startup and never exposed through the console.
//	VEILGATED_DEBUG_ADDR        Optional plaintext diagnostics address. Never expose
//	                            publicly; it serves unauthenticated profiling.
//	VEILGATED_NATS_URL          Optional NATS URL for durable audit publication.
//	VEILGATED_NATS_CERT/KEY/CA  Optional NATS mTLS material, falling back to the
//	                            matching VEILGATED_WORKLOAD_CERT/KEY/CA variables.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
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

const appName = "veilgated"

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

	policyPath := os.Getenv("VEILGATED_CLIENTS_FILE")
	if policyPath == "" {
		return errors.New("VEILGATED_CLIENTS_FILE is required")
	}
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
		responseHeaderTimeout = 30 * time.Second
	}
	if responseHeaderTimeout < time.Second || responseHeaderTimeout > 10*time.Minute {
		return errors.New("VEILGATED_UPSTREAM_RESPONSE_HEADER_TIMEOUT must be between 1s and 10m")
	}
	captureLimit, err := envutil.Int("VEILGATED_CAPTURE_LIMIT_BYTES")
	if err != nil {
		return err
	}
	if captureLimit == 0 {
		captureLimit = 256 << 10
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

	consoleUser := os.Getenv("VEILGATED_CONSOLE_USERNAME")
	consolePassword := os.Getenv("VEILGATED_CONSOLE_PASSWORD")
	if (consoleUser == "") != (consolePassword == "") {
		return errors.New("VEILGATED_CONSOLE_USERNAME and VEILGATED_CONSOLE_PASSWORD must be set together")
	}

	proxyCertPath := os.Getenv("VEILGATED_PROXY_CERT")
	proxyKeyPath := os.Getenv("VEILGATED_PROXY_KEY")
	if proxyCertPath == "" || proxyKeyPath == "" {
		return errors.New("VEILGATED_PROXY_CERT and VEILGATED_PROXY_KEY are required; the proxy does not serve plaintext HTTP")
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
	if policy.HasObservationClients() && interceptionAuthority == nil {
		return errors.New("observe_all_public_hosts requires TLS interception CA material")
	}

	var secretBroker *secret.Broker
	if secretsPath := os.Getenv("VEILGATED_SECRETS_FILE"); secretsPath != "" {
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
	if oauthPath := os.Getenv("VEILGATED_OAUTH_FILE"); oauthPath != "" {
		if interceptionAuthority == nil {
			return errors.New("VEILGATED_OAUTH_FILE requires TLS interception CA material")
		}
		authPath := envutil.Or("VEILGATED_AUTH_FILE", "/var/lib/veilgate/auth.json")
		oauthBroker, err = oauth.Load(oauthPath, authPath)
		if err != nil {
			return fmt.Errorf("load OAuth broker: %w", err)
		}
		rt.Log.Warn("OAuth broker enabled with plaintext auth state", "config", oauthPath, "auth_state", authPath, "encryption", "disabled")
	}
	broker := proxy.CombineBrokers(secretBroker, oauthBroker)

	store, err := flow.Open(rt.DB.URL, retention)
	if err != nil {
		return fmt.Errorf("open flow store: %w", err)
	}
	defer guard.Close(store)
	if rt.DB.URL == "" {
		rt.Log.Warn("VEILGATED_DATABASE_URL not set; flow retention is in memory")
	} else {
		rt.Log.Info("durable flow store enabled")
	}
	proxyHandler := &proxy.Handler{
		Policy:                        policy,
		Resolver:                      proxy.PublicResolver{},
		Store:                         store,
		Log:                           rt.Log,
		Interceptor:                   interceptionAuthority,
		Secrets:                       broker,
		OAuth:                         oauthBroker,
		DialTimeout:                   dialTimeout,
		SessionIdleTimeout:            sessionIdleTimeout,
		SessionMaxDuration:            sessionMaxDuration,
		UpstreamResponseHeaderTimeout: responseHeaderTimeout,
		CaptureLimit:                  int64(captureLimit),
		MediationLimit:                int64(mediationLimit),
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
	consoleCertPath := envutil.Or("VEILGATED_CONSOLE_CERT", "config/console.crt")
	consoleKeyPath := envutil.Or("VEILGATED_CONSOLE_KEY", "config/console.key")
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
	consoleAddr := envutil.Or("VEILGATED_CONSOLE_ADDR", "127.0.0.1:8081")
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
	rt.Log.Info("veilgate starting", "proxy_addr", proxyAddr, "console_addr", consoleAddr, "clients", len(policy.Clients), "observation_clients", observationClientCount(policy))
	return run.Group(rt.Ctx,
		run.HTTPServer(proxyServer, 10*time.Second, true),
		run.HTTPServer(consoleServer, 10*time.Second, true),
	)
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
	initCmd.Flags().StringVar(&certPath, "cert", "config/intercept-ca.crt", "certificate output path")
	initCmd.Flags().StringVar(&keyPath, "key", "config/intercept-ca.key", "private-key output path")

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
	signCmd.Flags().StringVar(&caCertPath, "ca-cert", "config/intercept-ca.crt", "interception CA certificate path")
	signCmd.Flags().StringVar(&caKeyPath, "ca-key", "config/intercept-ca.key", "interception CA private-key path")
	signCmd.Flags().StringVar(&proxyCertPath, "cert", "config/proxy.crt", "proxy certificate output path")
	signCmd.Flags().StringVar(&proxyKeyPath, "key", "config/proxy.key", "proxy private-key output path")
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
