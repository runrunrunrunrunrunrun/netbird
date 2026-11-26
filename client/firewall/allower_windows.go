//go:build windows

package firewall

import (
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
)

// interfaceAllower returns the Windows netsh-based interface allower.
// Netstack mode has no kernel TUN interface to expose in Windows Firewall.
func interfaceAllower(iface IFaceMapper, _ uint16) uspfilter.InterfaceAllower {
	if netstack.IsEnabled() {
		return nil
	}
	return uspfilter.NewWindowsInterfaceAllower(iface)
}
