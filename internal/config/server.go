package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

//ServerConfig is the top-level shape of tunneld's YAML config file
type ServerConfig struct {
	//ListenAddr is where the control connection (client dial-in) listens,
	//e.g. "0.0.0.0:7000".
	ListenAddr string `yaml:"listen_addr"`
	//TLS holds the certificate/key used for the control connection
	//If both are empty, tunneld generates a self-signed cert at startup and logs its
	//fingerprint so the client can pin it
	TLS TLSConfig `yaml:"tls"`
	// AuthTokens is the set of bearer tokens accepted from clients
	AuthTokens []string `yaml:"auth_tokens"`
	//AllowedPortRange restricts which remote ports clients may request,
	//so a compromised/misbehaving client can't bind arbitrary ports on
	//your EC2 box (e.g. 22, or something already in use)
	AllowedPortRange PortRange `yaml:"allowed_port_range"`
	//ACL is the single, global access-control rule set applied to all
	//tunnels (v1 deliberately has no per-tunnel overrides - coz i am assuming that if 
	// we block say a ip then it must a bad ip(threat) so yea.)
	ACL ACLConfig `yaml:"acl"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type PortRange struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

// ACLConfig is the global allow/deny rule set for inbound connections on
// exposed tunnel ports. Deny is evaluated first: if an incoming IP matches
// any DenyCIDRs entry, it is rejected outright. If Allow CIDRs is non-empty,
// the IP must *also* match one of those entries to be let through - this
// lets you lock a tunnel down to only your own IP if you want. If Allow is
// empty, every IP not explicitly denied is allowed.
type ACLConfig struct {
	AllowCIDRs []string `yaml:"allow_cidrs"`
	DenyCIDRs  []string `yaml:"deny_cidrs"`
}

// LoadServerConfig reads and validates a tunneld YAML config from path.
func LoadServerConfig(path string) (*ServerConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: invalid %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *ServerConfig) validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if len(c.AuthTokens) == 0 {
		return fmt.Errorf("at least one auth_tokens entry is required")
	}
	if c.AllowedPortRange.Min == 0 && c.AllowedPortRange.Max == 0 {
		// Default to the full unprivileged range if unset.
		c.AllowedPortRange = PortRange{Min: 1024, Max: 65535}
	}
	if c.AllowedPortRange.Min < 1 || c.AllowedPortRange.Max > 65535 ||
		c.AllowedPortRange.Min > c.AllowedPortRange.Max {
		return fmt.Errorf("allowed_port_range %d-%d is invalid",
			c.AllowedPortRange.Min, c.AllowedPortRange.Max)
	}
	for _, cidr := range c.ACL.AllowCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("acl.allow_cidrs: %q: %w", cidr, err)
		}
	}
	for _, cidr := range c.ACL.DenyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("acl.deny_cidrs: %q: %w", cidr, err)
		}
	}
	return nil
}

// InRange reports whether port falls within the server's allowed port range.
func (c *ServerConfig) InRange(port int) bool {
	return port >= c.AllowedPortRange.Min && port <= c.AllowedPortRange.Max
}