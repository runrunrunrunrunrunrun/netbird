//go:build !android

package net

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func applyLinuxControl(_, address string, c syscall.RawConn) error {
	if ifaceName := GetExternalOutboundInterface(); ifaceName != "" {
		if isLoopbackAddress(address) {
			return nil
		}
		var bindErr error
		if err := c.Control(func(fd uintptr) {
			bindErr = unix.BindToDevice(int(fd), ifaceName)
		}); err != nil {
			return fmt.Errorf("control: %w", err)
		}
		if bindErr != nil {
			return fmt.Errorf("bind to device %q: %w", ifaceName, bindErr)
		}
		return nil
	}
	return setRawSocketMark(c)
}

// SetSocketMark sets the SO_MARK option on the given socket connection
func SetSocketMark(conn syscall.Conn) error {
	if !AdvancedRouting() {
		return nil
	}

	sysconn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn: %w", err)
	}

	return setRawSocketMark(sysconn)
}

func setRawSocketMark(conn syscall.RawConn) error {
	var setErr error

	err := conn.Control(func(fd uintptr) {
		if !AdvancedRouting() {
			return
		}
		setErr = setSocketOptInt(int(fd))
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}

	if setErr != nil {
		return fmt.Errorf("set SO_MARK: %w", setErr)
	}

	return nil
}

func setSocketOptInt(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(ControlPlaneMark))
}
