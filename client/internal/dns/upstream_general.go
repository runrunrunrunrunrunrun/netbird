//go:build !android && !ios

package dns

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
	"github.com/netbirdio/netbird/client/internal/peer"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/shared/management/domain"
)

type upstreamResolver struct {
	*upstreamResolverBase
	wgIface WGIface
	nsNet   *wgbackend.NetstackNet
}

func newUpstreamResolver(
	ctx context.Context,
	wgIface WGIface,
	statusRecorder *peer.Status,
	_ *hostsDNSHolder,
	d domain.Domain,
) (*upstreamResolver, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder, d)
	var nsNet *wgbackend.NetstackNet
	if wgIface != nil {
		nsNet = wgIface.GetNet()
	}
	nonIOS := &upstreamResolver{
		upstreamResolverBase: upstreamResolverBase,
		wgIface:              wgIface,
		nsNet:                nsNet,
	}
	upstreamResolverBase.upstreamClient = nonIOS
	return nonIOS, nil
}

func (u *upstreamResolver) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	if u.nsNet != nil {
		if runtime.GOOS == "js" || u.isTunnelRoutedUpstream(upstream, u.wgIface) {
			start := time.Now()
			reply, err := ExchangeWithNetstack(ctx, u.nsNet, r, upstream)
			return reply, time.Since(start), err
		}

		// Public upstreams in netstack mode must bind via NetBird's external socket
		// control so they bypass an outer TUN (e.g. Xray tunIn) and do not loop.
		timeout := UpstreamTimeout
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
		nbDialer := nbnet.NewDialer()
		client := &dns.Client{
			Timeout: timeout,
			Dialer: &net.Dialer{
				Timeout: timeout,
				Control: func(network, address string, c syscall.RawConn) error {
					return nbDialer.Control(network, address, c)
				},
			},
		}
		return ExchangeWithFallback(ctx, client, r, upstream)
	}

	client := &dns.Client{
		Timeout: ClientTimeout,
	}
	return ExchangeWithFallback(ctx, client, r, upstream)
}

func GetClientPrivate(_ privateClientIface, _ netip.Addr, dialTimeout time.Duration) (*dns.Client, error) {
	return &dns.Client{
		Timeout: dialTimeout,
		Net:     "udp",
	}, nil
}
