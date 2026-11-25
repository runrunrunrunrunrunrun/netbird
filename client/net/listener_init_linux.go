//go:build !android

package net

// init configures the net.ListenerConfig Control function to set the fwmark or bind to the outbound device
func (l *ListenerConfig) init() {
	l.ListenConfig.Control = applyLinuxControl
}
