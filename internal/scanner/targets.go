package scanner

import (
	"fmt"
	"net/netip"
	"strings"
)

// maxCIDRHostBits caps CIDR expansion at a /16 (65,536 addresses) so a typo
// like 10.0.0.0/8 can't silently queue millions of probes.
const maxCIDRHostBits = 16

// ExpandTargets turns user input into a flat list of hosts.
// Each input may be a hostname, an IP address, or a CIDR block.
func ExpandTargets(inputs []string) ([]string, error) {
	var hosts []string

	for _, in := range inputs {
		in = strings.TrimSpace(in)
		if in == "" {
			continue
		}

		if !strings.Contains(in, "/") {
			hosts = append(hosts, in)
			continue
		}

		prefix, err := netip.ParsePrefix(in)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", in, err)
		}
		prefix = prefix.Masked()

		hostBits := prefix.Addr().BitLen() - prefix.Bits()
		if hostBits > maxCIDRHostBits {
			return nil, fmt.Errorf("CIDR %q is too large (max 65,536 addresses per block)", in)
		}

		var block []string
		for addr := prefix.Addr(); addr.IsValid() && prefix.Contains(addr); addr = addr.Next() {
			block = append(block, addr.String())
		}

		// For IPv4 blocks with 4+ addresses, drop network and broadcast.
		if prefix.Addr().Is4() && hostBits >= 2 && len(block) > 2 {
			block = block[1 : len(block)-1]
		}
		hosts = append(hosts, block...)
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}
	return hosts, nil
}
