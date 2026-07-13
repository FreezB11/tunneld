// Command tunneld runs the tunnel relay server. It is meant to run on the
// public EC2 instance: it listens for tunnel client connections and exposes
// registered tunnels on public ports.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tunnel/internal/auth"
	"tunnel/internal/config"
	"tunnel/internal/server"
)

func main() {
	configPath := flag.String("config", "tunneld.yml", "path to server YAML config")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("tunneld: %v", err)
	}

	authenticator := auth.NewTokenAuthenticator(cfg.AuthTokens)

	srv, err := server.New(cfg, authenticator)
	if err != nil {
		log.Fatalf("tunneld: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("tunneld: starting (config: %s)", *configPath)
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("tunneld: %v", err)
	}
	log.Printf("tunneld: shut down cleanly")
}
