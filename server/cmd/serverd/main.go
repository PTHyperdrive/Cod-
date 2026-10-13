// Command serverd is the Codé Team Server entry point.
//
// The Team Server runs two listeners:
//   1. A TLS listener on --listen that accepts agent connections using
//      the Codé TLV binary protocol.
//   2. A gRPC listener on --grpc-listen that serves the operator-facing
//      API with mutual TLS authentication.
//
// Both listeners share the same session manager, audit logger, and
// configuration.
//
// Usage:
//
//	serverd \
//	    --tls-cert  ../certs/server/server.crt \
//	    --tls-key   ../certs/server/server.key \
//	    --ca-cert   ../certs/ca/ca.crt \
//	    --listen    10.13.37.1:443 \
//	    --grpc-listen 10.13.37.1:50051 \
//	    --audit-log /var/log/code_audit.jsonl
//
// ACADEMIC/EDUCATIONAL USE ONLY.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/c2-framework/server/internal/audit"
	"github.com/c2-framework/server/internal/grpcapi"
	"github.com/c2-framework/server/internal/listener"
	"github.com/c2-framework/server/internal/session"
)

const banner = `
   ██████╗ ██████╗ ██████╗ ███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██║     ██║   ██║██║  ██║█████╗  
  ██║     ██║   ██║██║  ██║██╔══╝  
  ╚██████╗╚██████╔╝██████╔╝███████╗
   ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
                  Team Server v0.1.0
      ACADEMIC/EDUCATIONAL USE ONLY
`

func main() {
	// ── Flags ────────────────────────────────────────
	tlsCert := flag.String("tls-cert", "", "Path to server TLS certificate (PEM)")
	tlsKey := flag.String("tls-key", "", "Path to server TLS private key (PEM)")
	caCert := flag.String("ca-cert", "", "Path to CA certificate (PEM)")

	listenAddr := flag.String("listen", "0.0.0.0:443",
		"Address for the TLS agent listener")
	grpcAddr := flag.String("grpc-listen", "0.0.0.0:50051",
		"Address for the gRPC operator API")

	beaconInterval := flag.Uint("beacon-interval", 30,
		"Default beacon interval in seconds (sent to agents)")
	beaconJitter := flag.Uint("beacon-jitter", 20,
		"Default beacon jitter percentage 0–100 (sent to agents)")

	auditPath := flag.String("audit-log", "audit.jsonl",
		"Path to the append-only audit log file")

	flag.Parse()

	// ── Banner ──────────────────────────────────────
	fmt.Print(banner)

	// ── Validate required flags ─────────────────────
	if *tlsCert == "" || *tlsKey == "" || *caCert == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --tls-cert, --tls-key, and --ca-cert are required")
		flag.Usage()
		os.Exit(1)
	}

	// ── Audit logger ────────────────────────────────
	auditLog, err := audit.New(*auditPath)
	if err != nil {
		log.Fatalf("Failed to open audit log: %v", err)
	}
	defer auditLog.Close()

	auditLog.ServerEvent(audit.EventServerStart,
		fmt.Sprintf("listen=%s grpc=%s", *listenAddr, *grpcAddr))

	// ── Session manager ─────────────────────────────
	sessions := session.NewManager()

	// ── TLS agent listener ──────────────────────────
	lnCfg := listener.Config{
		ListenAddr:            *listenAddr,
		CertFile:              *tlsCert,
		KeyFile:               *tlsKey,
		CAFile:                *caCert,
		DefaultBeaconInterval: uint32(*beaconInterval),
		DefaultJitter:         uint8(*beaconJitter),
		RegisterTimeout:       listener.DefaultConfig().RegisterTimeout,
		FirstBeaconWait:       listener.DefaultConfig().FirstBeaconWait,
	}
	ln := listener.New(lnCfg, sessions, auditLog)

	// ── gRPC operator API ───────────────────────────
	grpcCfg := grpcapi.Config{
		ListenAddr: *grpcAddr,
		CertFile:   *tlsCert,
		KeyFile:    *tlsKey,
		CAFile:     *caCert,
	}
	grpcSrv := grpcapi.New(grpcCfg, sessions, auditLog)

	// ── Start listeners ─────────────────────────────
	errCh := make(chan error, 2)

	go func() {
		errCh <- ln.Start()
	}()

	go func() {
		errCh <- grpcSrv.Start()
	}()

	// ── Signal handling ─────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %v, shutting down...", sig)
	case err := <-errCh:
		if err != nil {
			log.Printf("Listener error: %v", err)
		}
	}

	// ── Graceful shutdown ───────────────────────────
	log.Println("Shutting down Team Server...")

	// Shut down all active sessions.
	count := sessions.ShutdownAll()
	log.Printf("Notified %d sessions of shutdown", count)

	// Stop listeners.
	ln.Stop()
	grpcSrv.Stop()

	auditLog.ServerEvent(audit.EventServerStop, "graceful shutdown complete")

	log.Println("Team Server stopped.")
}
