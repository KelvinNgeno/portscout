package scanner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePorts turns a port specification into a sorted, de-duplicated list.
//
// Supported forms (comma-separated, mixable):
//
//	80          a single port
//	1-1024      an inclusive range
//	top         the built-in list of common ports
//	all         every port, 1-65535
func ParsePorts(spec string) ([]int, error) {
	seen := make(map[int]struct{})

	add := func(p int) { seen[p] = struct{}{} }

	for _, part := range strings.Split(spec, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}

		switch {
		case part == "top":
			for _, p := range TopPorts {
				add(p)
			}
		case part == "all":
			for p := 1; p <= 65535; p++ {
				add(p)
			}
		case strings.Contains(part, "-"):
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("port range %q out of bounds (1-65535, low <= high)", part)
			}
			for p := lo; p <= hi; p++ {
				add(p)
			}
		default:
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port %d out of range (1-65535)", p)
			}
			add(p)
		}
	}

	if len(seen) == 0 {
		return nil, fmt.Errorf("no ports specified")
	}

	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}
