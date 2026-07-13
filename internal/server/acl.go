package server

import (
	"fmt"
	"net"

	"tunnel/internal/config"
)

// aclChecker holds pre-parsed CIDR sets so we're not re-parsing strings on
// every single incoming connection.
type aclChecker struct {
	allow []*net.IPNet
	deny  []*net.IPNet
}

func newACLChecker(cfg config.ACLConfig) (*aclChecker, error) {
	ac := &aclChecker{}
	for _, s := range cfg.AllowCIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("acl: parse allow cidr %q: %w", s, err)
		}
		ac.allow = append(ac.allow, n)
	}
	for _, s := range cfg.DenyCIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("acl: parse deny cidr %q: %w", s, err)
		}
		ac.deny = append(ac.deny, n)
	}
	return ac, nil
}

// Allowed reports whether ip is permitted to connect.
//
// Rules (deny-first):
//  1. If ip matches any deny CIDR, it is rejected.
//  2. Else, if an allow list is configured, ip must match one of its
//     entries to be permitted.
//  3. Else (no allow list configured, not denied), ip is permitted.
func (ac *aclChecker) Allowed(ip net.IP) bool {
	for _, n := range ac.deny {
		if n.Contains(ip) {
			return false
		}
	}
	if len(ac.allow) == 0 {
		return true
	}
	for _, n := range ac.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
