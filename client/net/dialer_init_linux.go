//go:build !android

package net

// init configures the net.Dialer Control function to set the fwmark or bind to the outbound device
func (d *Dialer) init() {
	d.Dialer.Control = applyLinuxControl
}
