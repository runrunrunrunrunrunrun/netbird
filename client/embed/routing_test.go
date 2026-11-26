package embed

import (
	"context"
	"net"
	"net/netip"
	"testing"

	miekgdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/route"
)

type fakeManagedDNSServer struct {
	nbdns.MockServer
	matched map[string]struct{}
	replies map[uint16]*miekgdns.Msg
	errs    map[uint16]error
}

func (f *fakeManagedDNSServer) MatchManagedDomain(domain string) bool {
	_, ok := f.matched[normalizeDomain(domain)]
	return ok
}

func (f *fakeManagedDNSServer) ResolveManagedDomain(_ context.Context, _ string, qtype uint16) (*miekgdns.Msg, error) {
	if err := f.errs[qtype]; err != nil {
		return nil, err
	}
	return f.replies[qtype], nil
}

func TestLookupManagedIP(t *testing.T) {
	srv := &fakeManagedDNSServer{
		matched: map[string]struct{}{
			"peer-a.netbird.selfhosted": {},
		},
		replies: map[uint16]*miekgdns.Msg{
			miekgdns.TypeA: {
				MsgHdr: miekgdns.MsgHdr{Rcode: miekgdns.RcodeSuccess},
				Answer: []miekgdns.RR{
					&miekgdns.A{
						Hdr: miekgdns.RR_Header{Ttl: 120, Rrtype: miekgdns.TypeA},
						A:   net.ParseIP("100.64.0.10").To4(),
					},
				},
			},
			miekgdns.TypeAAAA: {
				MsgHdr: miekgdns.MsgHdr{Rcode: miekgdns.RcodeSuccess},
				Answer: nil, // NODATA for AAAA on v4-only peer
			},
		},
	}

	// Both v4 and v6 enabled -> returns IPv4 address + min TTL.
	addrs, ttl, err := lookupManagedIP(context.Background(), srv, "PEER-A.netbird.selfhosted.", true, true)
	require.NoError(t, err)
	assert.Equal(t, uint32(120), ttl)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("100.64.0.10")}, addrs)

	// IPv6-only query on v4-only managed domain -> NODATA (nil, 0, nil).
	addrs, ttl, err = lookupManagedIP(context.Background(), srv, "peer-a.netbird.selfhosted", false, true)
	require.NoError(t, err)
	assert.Zero(t, ttl)
	assert.Empty(t, addrs)

	// Unmanaged domain -> error.
	_, _, err = lookupManagedIP(context.Background(), srv, "example.com", true, true)
	assert.Error(t, err)
}

func TestCollectBaseExitNodeIDs(t *testing.T) {
	v4Default := netip.MustParsePrefix("0.0.0.0/0")
	v6Default := netip.MustParsePrefix("::/0")
	lanPrefix := netip.MustParsePrefix("192.168.10.0/24")

	hm := route.HAMap{
		route.HAUniqueID("exit-b"): {
			{ID: "r1", NetID: "exit-b", Network: v4Default},
		},
		route.HAUniqueID("exit-b" + route.V6ExitSuffix): {
			{ID: "r1-v6", NetID: "exit-b" + route.V6ExitSuffix, Network: v6Default},
		},
		route.HAUniqueID("exit-a"): {
			{ID: "r2", NetID: "exit-a", Network: v4Default},
		},
		route.HAUniqueID("corp-lan"): {
			{ID: "r3", NetID: "corp-lan", Network: lanPrefix},
		},
	}

	assert.Equal(t, []route.NetID{"exit-a", "exit-b"}, collectBaseExitNodeIDs(hm))
	assert.Equal(t, []route.NetID{"exit-a", "exit-b", "exit-b-v6"}, collectAllSelectedExitIDs(hm))
}
