package system

import (
	"context"
	"os"
	"runtime"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

// UpdateStaticInfoAsync is a no-op on Android as there is no static info to update
func UpdateStaticInfoAsync() {
	// do nothing
}

// GetInfo retrieves and parses the system information without spawning subprocesses,
// avoiding Android 10/11 seccomp SIGSYS in os/exec pidfd checks and SELinux denials.
func GetInfo(ctx context.Context) *Info {
	kernel, kernelVersion := unameInfo()
	props := readBuildProps()

	addrs, err := networkAddresses()
	if err != nil {
		log.Warnf("discover network addresses: %s", err)
	}

	return &Info{
		GoOS:               runtime.GOOS,
		Kernel:             kernel,
		Platform:           "unknown",
		OS:                 "Android",
		OSVersion:          props["ro.build.version.release"],
		Hostname:           extractDeviceName(ctx, "android"),
		CPUs:               runtime.NumCPU(),
		NetbirdVersion:     version.NetbirdVersion(),
		UIVersion:          extractUIVersion(ctx),
		KernelVersion:      kernelVersion,
		NetworkAddresses:   addrs,
		SystemSerialNumber: "",
		SystemProductName:  props["ro.product.model"],
		SystemManufacturer: props["ro.product.manufacturer"],
	}
}

// checkFileAndProcess checks if the file path exists and if a process is running at that path.
func checkFileAndProcess(_ context.Context, _ []string) ([]File, error) {
	return []File{}, nil
}

func extractUIVersion(ctx context.Context) string {
	v, ok := ctx.Value(UiVersionCtxKey).(string)
	if !ok {
		return ""
	}
	return v
}

func unameInfo() (string, string) {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "android", ""
	}
	sysname := utsCharsToString(uts.Sysname)
	if sysname == "" {
		sysname = "android"
	}
	release := utsCharsToString(uts.Release)
	return sysname, release
}

func utsCharsToString[T ~int8 | ~uint8](arr [65]T) string {
	buf := make([]byte, 0, len(arr))
	for _, c := range arr {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return strings.TrimSpace(string(buf))
}

func readBuildProps() map[string]string {
	props := make(map[string]string)
	for _, path := range []string{"/system/build.prop", "/vendor/build.prop"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			if _, exists := props[k]; !exists {
				props[k] = strings.TrimSpace(v)
			}
		}
	}
	return props
}
