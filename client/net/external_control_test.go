package net

import "testing"

func TestExternalOutboundInterface(t *testing.T) {
	t.Cleanup(func() {
		SetExternalOutboundInterface("")
	})

	SetExternalOutboundInterface(" Ethernet 2 ")
	if got := GetExternalOutboundInterface(); got != "Ethernet 2" {
		t.Fatalf("GetExternalOutboundInterface() = %q, want %q", got, "Ethernet 2")
	}
	if !HasExternalSocketControl() {
		t.Fatal("HasExternalSocketControl() = false, want true")
	}

	SetExternalOutboundInterface("")
	if got := GetExternalOutboundInterface(); got != "" {
		t.Fatalf("GetExternalOutboundInterface() = %q, want empty", got)
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"", false},
		{":0", false},
		{"0.0.0.0:51820", false},
		{"[::]:51820", false},
		{"127.0.0.1:443", true},
		{"127.0.1.1:53", true},
		{"[::1]:8080", true},
		{"[::ffff:127.0.0.1]:443", true},
		{"localhost:8443", true},
		{"LOCALHOST", true},
		{"1.1.1.1:443", false},
		{"[2606:4700:4700::1111]:443", false},
		{"net.l0op.site:443", false},
	}

	for _, tc := range tests {
		if got := isLoopbackAddress(tc.addr); got != tc.want {
			t.Errorf("isLoopbackAddress(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
