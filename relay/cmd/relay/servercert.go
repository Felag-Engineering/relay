// The names on the Relay's one server certificate (ADR-0031 §2).
package main

import (
	"fmt"
	"net"
)

// maxDetectedAddresses bounds how many of the host's addresses the certificate
// names: a host with many service addresses (an IPVS dummy interface, say) must
// not grow the leaf without bound. The hostname and loopback are never counted
// against it.
const maxDetectedAddresses = 64

// serverCertNames is the SAN set for the Relay's server certificate.
type serverCertNames struct {
	DNSNames    []string
	IPAddresses []net.IP
	// Omitted counts detected addresses left off because of maxDetectedAddresses.
	Omitted int
}

// serverCertificateNames returns the names the server certificate carries:
// tls.hostname (an IP SAN when it is an IP address, a DNS SAN otherwise), the
// loopback addresses, and up to maxDetectedAddresses of the host's usable
// unicast addresses, IPv4 first because a relay-daemon can dial an IPv4
// literal today and cannot dial an IPv6 one without a server name override, so
// the cap drops the less usable family first.
//
// Loopback is listed once, explicitly; every other loopback, multicast and
// unspecified address is skipped, as is link-local: IPv6 fe80::/10 is only
// meaningful with a zone, which a SAN cannot carry, and IPv4 169.254/16 is
// self-assigned and unstable, not something a Node should be told to dial.
//
// The addresses are read once, when this is called; a host that gains one
// afterwards needs a restart for the certificate to name it. When
// interfaceAddrs fails the result still holds the hostname and loopback names,
// returned beside the error so the caller decides whether that is fatal.
func serverCertificateNames(hostname string, interfaceAddrs func() ([]net.Addr, error)) (serverCertNames, error) {
	var names serverCertNames
	seen := map[string]bool{}
	add := func(ip net.IP) {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		names.IPAddresses = append(names.IPAddresses, ip)
	}

	if ip := net.ParseIP(hostname); ip != nil {
		add(ip)
	} else {
		names.DNSNames = []string{hostname}
	}
	add(net.IPv4(127, 0, 0, 1))
	add(net.IPv6loopback)

	addrs, err := interfaceAddrs()
	if err != nil {
		return names, fmt.Errorf("list this host's addresses: %w", err)
	}

	var v4, v6 []net.IP
	for _, a := range addrs {
		var ip net.IP
		switch a := a.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if !usableDetectedAddress(ip) || seen[ip.String()] {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			seen[ip4.String()] = true
			v4 = append(v4, ip4)
			continue
		}
		seen[ip.String()] = true
		v6 = append(v6, ip)
	}

	detected := append(v4, v6...)
	if len(detected) > maxDetectedAddresses {
		names.Omitted = len(detected) - maxDetectedAddresses
		detected = detected[:maxDetectedAddresses]
	}
	names.IPAddresses = append(names.IPAddresses, detected...)
	return names, nil
}

func usableDetectedAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsInterfaceLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified()
}

// ipStrings renders addresses for the startup log.
func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
