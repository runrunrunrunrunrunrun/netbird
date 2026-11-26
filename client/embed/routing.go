package embed

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	miekgdns "github.com/miekg/dns"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/route"
)

// ErrDNSFallthrough indicates NetBird did not produce an answer and the caller
// should fall through to normal/upstream DNS resolution.
var ErrDNSFallthrough = errors.New("netbird dns fallthrough")

// DNSRcodeError reports an authoritative non-success DNS response code returned
// by NetBird's managed DNS handlers.
type DNSRcodeError struct {
	Domain string
	Rcode  int
}

func (e *DNSRcodeError) Error() string {
	return fmt.Sprintf("netbird dns lookup for %q failed: rcode=%s", e.Domain, miekgdns.RcodeToString[e.Rcode])
}

// DNSRcode implements interfaces expecting the numeric DNS response code.
func (e *DNSRcodeError) DNSRcode() int {
	return e.Rcode
}

// RoutingTable summarizes the active NetBird overlay networks, routed CIDRs,
// dynamic route domains, exit-node availability, and managed DNS domains.
type RoutingTable struct {
	OverlayPrefixes  []netip.Prefix
	ClientPrefixes   []netip.Prefix
	ExitNodeV4       bool
	ExitNodeV6       bool
	ExitNodeIDs      []string
	SelectedExitNode string
	RouteDomains     []string
	DNSDomains       []string
	SearchDomains    []string
	HasDefaultDNS    bool
	PeerFQDNs        []string
}

func normalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func isExitNodeRoute(r *route.Route) bool {
	return r != nil && !r.IsDynamic() && (route.IsV4DefaultRoute(r.Network) || route.IsV6DefaultRoute(r.Network))
}

func collectBaseExitNodeIDs(hm route.HAMap) []route.NetID {
	seen := make(map[route.NetID]struct{})
	var ids []route.NetID
	for haID, routes := range hm {
		if !slices.ContainsFunc(routes, isExitNodeRoute) {
			continue
		}
		netID := haID.NetID()
		if strings.HasSuffix(string(netID), route.V6ExitSuffix) {
			continue
		}
		if _, ok := seen[netID]; ok {
			continue
		}
		seen[netID] = struct{}{}
		ids = append(ids, netID)
	}
	slices.Sort(ids)
	return ids
}

func collectAllSelectedExitIDs(hm route.HAMap) []route.NetID {
	seen := make(map[route.NetID]struct{})
	var ids []route.NetID
	for haID, routes := range hm {
		if !slices.ContainsFunc(routes, isExitNodeRoute) {
			continue
		}
		netID := haID.NetID()
		if _, ok := seen[netID]; ok {
			continue
		}
		seen[netID] = struct{}{}
		ids = append(ids, netID)
	}
	slices.Sort(ids)
	return ids
}

// reconcileExitNodeSelection aligns the route manager's exit-node selection
// with c.enableExitNode.
func (c *Client) reconcileExitNodeSelection() {
	c.exitNodeMu.Lock()
	defer c.exitNodeMu.Unlock()

	engine, err := c.getEngine()
	if err != nil {
		return
	}
	rm := engine.GetRouteManager()
	if rm == nil {
		return
	}

	allBase := collectBaseExitNodeIDs(rm.GetClientRoutes())
	if len(allBase) == 0 && !c.enableExitNode {
		if selected := collectAllSelectedExitIDs(rm.GetSelectedClientRoutes()); len(selected) > 0 {
			_ = rm.DeselectRoutes(selected)
		}
		return
	}

	selected := collectAllSelectedExitIDs(rm.GetSelectedClientRoutes())
	if !c.enableExitNode {
		if len(selected) > 0 {
			_ = rm.DeselectRoutes(selected)
		}
		return
	}

	if len(allBase) > 0 && len(selected) == 0 {
		_ = rm.SelectRoutes([]route.NetID{allBase[0]}, true)
	}
}

// RoutingTable returns the current overlay prefixes, active client routes,
// exit-node state, and NetBird-managed domains.
func (c *Client) RoutingTable() (RoutingTable, error) {
	engine, err := c.getEngine()
	if err != nil {
		return RoutingTable{}, err
	}

	c.reconcileExitNodeSelection()

	var table RoutingTable
	table.OverlayPrefixes = engine.GetOverlayPrefixes()

	clientPrefixSeen := make(map[netip.Prefix]struct{})
	addClientPrefix := func(p netip.Prefix) {
		if !p.IsValid() {
			return
		}
		if _, ok := clientPrefixSeen[p]; ok {
			return
		}
		clientPrefixSeen[p] = struct{}{}
		table.ClientPrefixes = append(table.ClientPrefixes, p)
	}

	routeDomainSeen := make(map[string]struct{})
	addRouteDomain := func(d string) {
		norm := normalizeDomain(d)
		if norm == "" {
			return
		}
		if _, ok := routeDomainSeen[norm]; ok {
			return
		}
		routeDomainSeen[norm] = struct{}{}
		table.RouteDomains = append(table.RouteDomains, norm)
	}

	if rm := engine.GetRouteManager(); rm != nil {
		for _, id := range collectBaseExitNodeIDs(rm.GetClientRoutes()) {
			table.ExitNodeIDs = append(table.ExitNodeIDs, string(id))
		}

		for haID, routes := range rm.GetSelectedClientRoutes() {
			for _, r := range routes {
				if r == nil {
					continue
				}
				if r.IsDynamic() {
					for _, d := range r.Domains.ToPunycodeList() {
						addRouteDomain(d)
					}
					continue
				}
				if route.IsV4DefaultRoute(r.Network) {
					if c.enableExitNode {
						table.ExitNodeV4 = true
						if table.SelectedExitNode == "" {
							table.SelectedExitNode = string(haID.NetID())
						}
					}
					continue
				}
				if route.IsV6DefaultRoute(r.Network) {
					if c.enableExitNode {
						table.ExitNodeV6 = true
						if table.SelectedExitNode == "" {
							table.SelectedExitNode = strings.TrimSuffix(string(haID.NetID()), route.V6ExitSuffix)
						}
					}
					continue
				}
				addClientPrefix(r.Network)
			}
		}
	}

	if c.recorder != nil {
		for _, p := range c.recorder.GetResolvedDomainPrefixes() {
			addClientPrefix(p)
		}
		table.PeerFQDNs = c.recorder.GetPeerFQDNs()
	}

	if dnsSrv := engine.GetDNSServer(); dnsSrv != nil {
		table.DNSDomains = dnsSrv.ManagedDomains()
		table.SearchDomains = normalizedDomains(dnsSrv.SearchDomains())
		table.HasDefaultDNS = dnsSrv.HasDefaultUpstream()
	}

	slices.Sort(table.RouteDomains)
	return table, nil
}

func normalizedDomains(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, d := range raw {
		norm := normalizeDomain(d)
		if norm == "" || norm == "." {
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	slices.Sort(out)
	return out
}

// HasDefaultDNS reports whether NetBird has a primary ("All domains") nameserver group.
func (c *Client) HasDefaultDNS() bool {
	engine, err := c.getEngine()
	if err != nil {
		return false
	}
	dnsSrv := engine.GetDNSServer()
	return dnsSrv != nil && dnsSrv.HasDefaultUpstream()
}

// SearchDomains returns normalized NetBird search domains.
func (c *Client) SearchDomains() []string {
	engine, err := c.getEngine()
	if err != nil {
		return nil
	}
	dnsSrv := engine.GetDNSServer()
	if dnsSrv == nil {
		return nil
	}
	return normalizedDomains(dnsSrv.SearchDomains())
}

// MatchDNSDomain reports whether domain is owned by NetBird's managed DNS
// (peer FQDNs, matching short hostnames, custom zones, explicit NS group domains,
// or dynamic route domains).
func (c *Client) MatchDNSDomain(domain string) bool {
	norm := normalizeDomain(domain)
	if norm == "" {
		return false
	}
	var dnsSrv nbdns.Server
	if engine, err := c.getEngine(); err == nil {
		dnsSrv = engine.GetDNSServer()
	}
	if dnsSrv != nil && dnsSrv.MatchManagedDomain(norm) {
		return true
	}
	if c.recorder != nil {
		if _, _, ok := c.recorder.LookupPeerIPsByFQDN(norm); ok {
			return true
		}
	}
	if !strings.Contains(norm, ".") {
		if c.recorder != nil {
			if _, _, _, ok := c.recorder.LookupPeerByShortName(norm); ok {
				return true
			}
		}
		if dnsSrv != nil {
			for _, sd := range normalizedDomains(dnsSrv.SearchDomains()) {
				cand := normalizeDomain(norm + "." + sd)
				if dnsSrv.HasLocalRecord(cand) {
					return true
				}
			}
		}
	}
	return false
}

func (c *Client) lookupPeerIPs(fqdn string, ipv4, ipv6 bool) ([]netip.Addr, bool) {
	if c.recorder == nil {
		return nil, false
	}
	v4, v6, ok := c.recorder.LookupPeerIPsByFQDN(fqdn)
	if !ok {
		return nil, false
	}
	return filterAddrPair(v4, v6, ipv4, ipv6), true
}

func filterAddrPair(v4, v6 netip.Addr, wantV4, wantV6 bool) []netip.Addr {
	var addrs []netip.Addr
	if wantV4 && v4.IsValid() {
		addrs = append(addrs, v4)
	}
	if wantV6 && v6.IsValid() {
		addrs = append(addrs, v6)
	}
	return addrs
}

func (c *Client) expandShortName(label string, dnsSrv nbdns.Server) (fqdn string, v4, v6 netip.Addr, hasPeer bool) {
	if label == "" || strings.Contains(label, ".") {
		return "", netip.Addr{}, netip.Addr{}, false
	}
	if dnsSrv != nil {
		for _, sd := range normalizedDomains(dnsSrv.SearchDomains()) {
			cand := normalizeDomain(label + "." + sd)
			if dnsSrv.HasLocalRecord(cand) {
				if c.recorder != nil {
					v4, v6, hasPeer = c.recorder.LookupPeerIPsByFQDN(cand)
				}
				return cand, v4, v6, hasPeer
			}
		}
	}
	if c.recorder != nil {
		return c.recorder.LookupPeerByShortName(label)
	}
	return "", netip.Addr{}, netip.Addr{}, false
}

// LookupIP resolves a NetBird-managed domain directly against the embedded
// DNS server or known peer table without touching the OS resolver. Returns
// (nil, 0, nil) for managed NODATA, or wraps ErrDNSFallthrough when non-authoritative
// resolution should fall through to Xray's normal DNS.
func (c *Client) LookupIP(ctx context.Context, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error) {
	norm := normalizeDomain(domain)
	if norm == "" {
		return nil, 0, fmt.Errorf("%w: empty domain", ErrDNSFallthrough)
	}

	engine, err := c.getEngine()
	if err != nil {
		if addrs, ok := c.lookupPeerIPs(norm, ipv4, ipv6); ok {
			return addrs, 60, nil
		}
		if _, v4, v6, ok := c.expandShortName(norm, nil); ok {
			return filterAddrPair(v4, v6, ipv4, ipv6), 60, nil
		}
		return nil, 0, err
	}

	dnsSrv := engine.GetDNSServer()
	target := norm
	var shortPeerV4, shortPeerV6 netip.Addr
	var hasShortPeer bool
	if !strings.Contains(norm, ".") {
		if expanded, v4, v6, ok := c.expandShortName(norm, dnsSrv); expanded != "" {
			target = expanded
			shortPeerV4, shortPeerV6, hasShortPeer = v4, v6, ok
		}
	}

	if dnsSrv != nil && dnsSrv.MatchManagedDomain(target) {
		addrs, ttl, lErr := lookupManagedIP(ctx, dnsSrv, target, ipv4, ipv6)
		if lErr == nil {
			if len(addrs) > 0 {
				return addrs, ttl, nil
			}
			// Check peer table if the DNS server had no records of the requested family yet.
			if peerAddrs, ok := c.lookupPeerIPs(target, ipv4, ipv6); ok && len(peerAddrs) > 0 {
				return peerAddrs, 60, nil
			}
			return nil, 0, nil
		}

		// Non-authoritative fallthrough or NXDOMAIN rescue from peer table.
		var rcErr *DNSRcodeError
		if errors.Is(lErr, ErrDNSFallthrough) || (errors.As(lErr, &rcErr) && rcErr.Rcode == miekgdns.RcodeNameError) {
			if peerAddrs, ok := c.lookupPeerIPs(target, ipv4, ipv6); ok {
				return peerAddrs, 60, nil
			}
			if hasShortPeer {
				return filterAddrPair(shortPeerV4, shortPeerV6, ipv4, ipv6), 60, nil
			}
		}

		if errors.Is(lErr, ErrDNSFallthrough) && dnsSrv.HasDefaultUpstream() {
			if defAddrs, defTTL, defErr := lookupDefaultIP(ctx, dnsSrv, target, ipv4, ipv6); defErr == nil {
				return defAddrs, defTTL, nil
			} else if !errors.Is(defErr, ErrDNSFallthrough) {
				return nil, 0, defErr
			}
		}
		return nil, 0, lErr
	}

	if peerAddrs, ok := c.lookupPeerIPs(target, ipv4, ipv6); ok {
		return peerAddrs, 60, nil
	}
	if hasShortPeer {
		return filterAddrPair(shortPeerV4, shortPeerV6, ipv4, ipv6), 60, nil
	}
	return nil, 0, fmt.Errorf("%w: %q is not managed by netbird dns", ErrDNSFallthrough, domain)
}

// LookupDefaultIP resolves domain via NetBird's primary ("All domains")
// nameserver group and search-domain expansion.
func (c *Client) LookupDefaultIP(ctx context.Context, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error) {
	norm := normalizeDomain(domain)
	if norm == "" {
		return nil, 0, fmt.Errorf("%w: empty domain", ErrDNSFallthrough)
	}
	engine, err := c.getEngine()
	if err != nil {
		return nil, 0, err
	}
	dnsSrv := engine.GetDNSServer()
	if dnsSrv == nil {
		return nil, 0, fmt.Errorf("%w: netbird dns server not initialized", ErrDNSFallthrough)
	}

	if !strings.Contains(norm, ".") {
		for _, sd := range normalizedDomains(dnsSrv.SearchDomains()) {
			cand := normalizeDomain(norm + "." + sd)
			if dnsSrv.MatchManagedDomain(cand) {
				if addrs, ttl, mErr := lookupManagedIP(ctx, dnsSrv, cand, ipv4, ipv6); mErr == nil && len(addrs) > 0 {
					return addrs, ttl, nil
				}
			}
			if dnsSrv.HasDefaultUpstream() {
				if addrs, ttl, dErr := lookupDefaultIP(ctx, dnsSrv, cand, ipv4, ipv6); dErr == nil && len(addrs) > 0 {
					return addrs, ttl, nil
				}
			}
		}
	}

	if !dnsSrv.HasDefaultUpstream() {
		return nil, 0, fmt.Errorf("%w: no default netbird upstream configured", ErrDNSFallthrough)
	}
	return lookupDefaultIP(ctx, dnsSrv, norm, ipv4, ipv6)
}

func lookupManagedIP(ctx context.Context, dnsSrv nbdns.Server, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error) {
	norm := normalizeDomain(domain)
	if norm == "" || !dnsSrv.MatchManagedDomain(norm) {
		return nil, 0, fmt.Errorf("%w: domain %q is not managed by netbird dns", ErrDNSFallthrough, domain)
	}
	return queryHandlerIPs(ctx, norm, dnsSrv.ResolveManagedDomain, ipv4, ipv6)
}

func lookupDefaultIP(ctx context.Context, dnsSrv nbdns.Server, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error) {
	norm := normalizeDomain(domain)
	if norm == "" || !dnsSrv.HasDefaultUpstream() {
		return nil, 0, fmt.Errorf("%w: no default upstream for %q", ErrDNSFallthrough, domain)
	}
	return queryHandlerIPs(ctx, norm, dnsSrv.ResolveDefaultDomain, ipv4, ipv6)
}

func queryHandlerIPs(
	ctx context.Context,
	norm string,
	resolveFn func(context.Context, string, uint16) (*miekgdns.Msg, error),
	ipv4, ipv6 bool,
) ([]netip.Addr, uint32, error) {
	if !ipv4 && !ipv6 {
		return nil, 0, nil
	}

	var qtypes []uint16
	if ipv4 {
		qtypes = append(qtypes, miekgdns.TypeA)
	}
	if ipv6 {
		qtypes = append(qtypes, miekgdns.TypeAAAA)
	}

	var (
		addrs     []netip.Addr
		seen      = make(map[netip.Addr]struct{})
		minTTL    uint32
		hasTTL    bool
		anyNoErr  bool
		lastErr   error
		lastRcode int
	)

	for _, qtype := range qtypes {
		resp, err := resolveFn(ctx, norm, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			continue
		}
		lastRcode = resp.Rcode
		if resp.Rcode != miekgdns.RcodeSuccess {
			continue
		}
		anyNoErr = true
		for _, rr := range resp.Answer {
			var addr netip.Addr
			var ttl uint32
			switch rec := rr.(type) {
			case *miekgdns.A:
				if !ipv4 {
					continue
				}
				parsed, ok := netip.AddrFromSlice(rec.A)
				if !ok {
					continue
				}
				addr = parsed.Unmap()
				ttl = rec.Hdr.Ttl
			case *miekgdns.AAAA:
				if !ipv6 {
					continue
				}
				parsed, ok := netip.AddrFromSlice(rec.AAAA)
				if !ok {
					continue
				}
				addr = parsed.Unmap()
				ttl = rec.Hdr.Ttl
			default:
				continue
			}
			if !addr.IsValid() {
				continue
			}
			if _, exists := seen[addr]; !exists {
				seen[addr] = struct{}{}
				addrs = append(addrs, addr)
			}
			if ttl > 0 && (!hasTTL || ttl < minTTL) {
				minTTL = ttl
				hasTTL = true
			}
		}
	}

	if len(addrs) > 0 {
		if !hasTTL {
			minTTL = 60
		}
		return addrs, minTTL, nil
	}
	if anyNoErr {
		return nil, 0, nil
	}
	if lastErr != nil {
		if errors.Is(lastErr, nbdns.ErrNoManagedHandler) {
			return nil, 0, fmt.Errorf("%w: %w", ErrDNSFallthrough, lastErr)
		}
		return nil, 0, lastErr
	}
	return nil, 0, &DNSRcodeError{Domain: norm, Rcode: lastRcode}
}
