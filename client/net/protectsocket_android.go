package net

import (
	"fmt"
	"sync"
	"syscall"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

var (
	androidProtectSocketLock sync.Mutex
	androidProtectSocket     func(fd int32) bool
)

func SetAndroidProtectSocketFn(fn func(fd int32) bool) {
	androidProtectSocketLock.Lock()
	androidProtectSocket = fn
	androidProtectSocketLock.Unlock()
}

func hasAndroidProtectSocket() bool {
	androidProtectSocketLock.Lock()
	defer androidProtectSocketLock.Unlock()
	return androidProtectSocket != nil
}

// ControlProtectSocket protects sockets through the Android VpnService callback.
func ControlProtectSocket(_, address string, c syscall.RawConn) error {
	if isLoopbackAddress(address) {
		return nil
	}
	var aErr error
	err := c.Control(func(fd uintptr) {
		androidProtectSocketLock.Lock()
		defer androidProtectSocketLock.Unlock()

		if androidProtectSocket == nil {
			if netstack.IsEnabled() {
				return
			}
			aErr = fmt.Errorf("socket protection function not set")
			return
		}

		if !androidProtectSocket(int32(fd)) {
			aErr = fmt.Errorf("failed to protect socket via Android")
		}
	})

	if err != nil {
		return err
	}

	return aErr
}
