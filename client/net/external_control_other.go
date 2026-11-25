//go:build !android

package net

func hasPlatformExternalSocketControl() bool {
	return false
}
