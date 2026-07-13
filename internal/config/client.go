package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ClientConfig is the top-level shape of the tunnel client's YAML config file.
type ClientConfig struct {
	// Server is the tunneld control address to dial, e.g. "1.2.3.4:7000".
	Server string `yaml:"server"`

	// AuthToken is the bearer token sent during the hello handshake. Must
	// match one entry in the server's auth_tokens.
	AuthToken string `yaml:"auth_token"`

	// ClientName identifies this client in server logs. Purely cosmetic.
	ClientName string `yaml:"client_name"`

	// InsecureSkipVerify disables TLS certificate verification. Needed
	// when the server is using a self-signed cert and you have not
	// pinned its fingerprint via ServerFingerprint. Not recommended
	// beyond initial setup/testing.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	// ServerFingerprint, if set, pins the server's TLS certificate by its
	// SHA-256 fingerprint (hex), so a self-signed cert can be trusted
	// safely without disabling verification entirely. tunneld prints
	// this fingerprint on startup.
	ServerFingerprint string `yaml:"server_fingerprint"`

	// Tunnels is the list of local services to expose.
	Tunnels []TunnelConfig `yaml:"tunnels"`
}

// TunnelConfig describes one local service to expose through the tunnel.
type TunnelConfig struct {
	// Name identifies this tunnel in logs and in the protocol handshake.
	// Must be unique within the client config.
	Name string `yaml:"name"`

	// Type is "tcp" or "http". In v1 both are proxied identically at the
	// byte level; see protocol.TunnelType doc comment for why the
	// distinction still exists.
	Type string `yaml:"type"`

	// LocalAddr is the local address to forward to, e.g. "127.0.0.1:3000".
	LocalAddr string `yaml:"local_addr"`

	// RemotePort is the port to request on the server's public interface.
	// Must fall within the server's allowed_port_range or the server
	// will reject this tunnel.
	RemotePort int `yaml:"remote_port"`
}

// LoadClientConfig reads and validates a tunnel client YAML config from path.
func LoadClientConfig(path string) (*ClientConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg ClientConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: invalid %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *ClientConfig) validate() error {
	if c.Server == "" {
		return fmt.Errorf("server is required")
	}
	if c.AuthToken == "" {
		return fmt.Errorf("auth_token is required")
	}
	if len(c.Tunnels) == 0 {
		return fmt.Errorf("at least one tunnel must be configured")
	}
	seen := make(map[string]bool, len(c.Tunnels))
	for i, t := range c.Tunnels {
		if t.Name == "" {
			return fmt.Errorf("tunnels[%d]: name is required", i)
		}
		if seen[t.Name] {
			return fmt.Errorf("tunnels[%d]: duplicate tunnel name %q", i, t.Name)
		}
		seen[t.Name] = true
		if t.Type != "tcp" && t.Type != "http" {
			return fmt.Errorf("tunnels[%d] (%s): type must be \"tcp\" or \"http\", got %q", i, t.Name, t.Type)
		}
		if t.LocalAddr == "" {
			return fmt.Errorf("tunnels[%d] (%s): local_addr is required", i, t.Name)
		}
		if t.RemotePort <= 0 || t.RemotePort > 65535 {
			return fmt.Errorf("tunnels[%d] (%s): remote_port %d is invalid", i, t.Name, t.RemotePort)
		}
	}
	return nil
}
