// Command tunnel runs the tunnel client. It is meant to run on your local
// machine: it dials out to a tunneld server, registers the tunnels defined
// in its config, and forwards proxied connections to local services.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tunnel/internal/client"
	"tunnel/internal/config"
)

func main() {
	configPath := flag.String("config", "tunnel.yml", "path to client YAML config")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("tunnel: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	const retryDelay = 5 * time.Second

	for {
		c := client.New(cfg)
		err := c.Run(ctx)

		select {
		case <-ctx.Done():
			log.Printf("tunnel: shutting down")
			return
		default:
		}

		if err != nil {
			log.Printf("tunnel: connection lost: %v", err)
		}
		log.Printf("tunnel: reconnecting in %s...", retryDelay)

		select {
		case <-ctx.Done():
			return
		case <-time.After(retryDelay):
		}
	}
}
