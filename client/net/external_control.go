package net

import (
	"net"
	"net/netip"
	"strings"
	"sync"
)

var (
	externalOutboundIfaceMu sync.RWMutex
	externalOutboundIface   string
)

// SetExternalOutboundInterface configures an explicit physical outbound
// interface name for NetBird's control-plane, relay, ICE, and WireGuard sockets
// when embedded inside an external TUN/VPN host such as Xray.
func SetExternalOutboundInterface(name string) {
	externalOutboundIfaceMu.Lock()
	externalOutboundIface = strings.TrimSpace(name)
	externalOutboundIfaceMu.Unlock()
}

// GetExternalOutboundInterface returns the configured external outbound
// interface name, or an empty string if none is set.
func GetExternalOutboundInterface() string {
	externalOutboundIfaceMu.RLock()
	defer externalOutboundIfaceMu.RUnlock()
	return externalOutboundIface
}

// HasExternalSocketControl reports whether an external host has registered
// socket-level bypass/binding (an explicit outbound interface or Android socket
// protection callback), even when NetBird itself runs in netstack mode.
func HasExternalSocketControl() bool {
	return GetExternalOutboundInterface() != "" || hasPlatformExternalSocketControl()
}

func isLoopbackAddress(address string) bool {
	addrStr := strings.TrimSpace(address)
	if addrStr == "" {
		return false
	}
	if addrPort, err := netip.ParseAddrPort(addrStr); err == nil {
		return addrPort.Addr().Unmap().IsLoopback()
	}
	if addr, err := netip.ParseAddr(addrStr); err == nil {
		return addr.Unmap().IsLoopback()
	}
	host, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		host = addrStr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().IsLoopback()
	}
	return false
}
