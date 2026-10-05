package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/bolaum/ghgw/internal/gateway"
	"github.com/spf13/cobra"
)

type serveOptions struct {
	listen, certFile, keyFile, policy, stateDir string
	// gitURL, apiURL and rootCAs are where git and REST requests go: GitHub, or a fake GitHub in
	// tests.
	gitURL, apiURL string
	rootCAs        *x509.CertPool
}

func newServeCmd() *cobra.Command {
	o := serveOptions{gitURL: gateway.DefaultGitURL, apiURL: gateway.DefaultAPIURL}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the gateway",
		Long: "Run the gateway listener: git fetch and clone, and gh api, through ghgw, for the users of\n" +
			"the policy file and with the credentials of the owners in the local store. The policy file\n" +
			"is read again when it changes, and so are the TLS certificate and key files; owners added or\n" +
			"removed with ghgw owner count from the next request. The log goes to stdout.",
		Example: "  ghgw serve --tls-cert /etc/ghgw/cert.pem --tls-key /etc/ghgw/key.pem\n" +
			"  ghgw serve --listen 127.0.0.1:8443 --tls-cert cert.pem --tls-key key.pem --policy policy.yaml",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.certFile == "" || o.keyFile == "" {
				return errors.New("serve needs --tls-cert and --tls-key: the gateway is HTTPS only (gh refuses plain HTTP)")
			}
			ln, err := net.Listen("tcp", o.listen)
			if err != nil {
				return err
			}
			return serve(cmd.Context(), o, ln, newLogger(cmd.OutOrStdout()))
		},
	}
	cmd.Flags().StringVar(&o.listen, "listen", ":8443", "address of the gateway listener")
	cmd.Flags().StringVar(&o.certFile, "tls-cert", "", "TLS certificate file (PEM, with its chain)")
	cmd.Flags().StringVar(&o.keyFile, "tls-key", "", "TLS key file (PEM)")
	addPolicyFlag(cmd, &o.policy)
	addStateDirFlag(cmd, &o.stateDir)
	return cmd
}

// serve runs the gateway on ln until ctx is done. ln is closed when serve returns.
func serve(ctx context.Context, o serveOptions, ln net.Listener, log *slog.Logger) error {
	defer ln.Close()
	cert, err := gateway.LoadCertificate(o.certFile, o.keyFile, log)
	if err != nil {
		return err
	}
	policy, err := policyPath(o.policy)
	if err != nil {
		return err
	}
	s, err := openStore(ctx, o.stateDir)
	if err != nil {
		return err
	}
	defer s.Close()
	gw, err := gateway.New(ctx, gateway.Config{
		PolicyPath: policy,
		Store:      s,
		GitURL:     o.gitURL,
		APIURL:     o.apiURL,
		RootCAs:    o.rootCAs,
		Logger:     log,
	})
	if err != nil {
		return policyErr(policy, err)
	}
	log.Info("serving", "addr", ln.Addr().String(), "policy", policy)
	if err := gateway.Serve(ctx, ln, gw, cert, log); err != nil {
		return err
	}
	log.Info("stopped")
	return nil
}

// newLogger logs to w: text on a terminal, JSON otherwise (SPEC.md section 15).
func newLogger(w io.Writer) *slog.Logger {
	if f, ok := w.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return slog.New(slog.NewTextHandler(w, nil))
		}
	}
	return slog.New(slog.NewJSONHandler(w, nil))
}
