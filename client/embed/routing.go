package embed

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	miekgdns "github.com/miekg/dns"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/route"
)

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
	}

	slices.Sort(table.RouteDomains)
	return table, nil
}

// MatchDNSDomain reports whether domain is owned by NetBird's managed DNS
// (peer FQDNs, custom zones, explicit NS group domains, or dynamic route domains).
func (c *Client) MatchDNSDomain(domain string) bool {
	norm := normalizeDomain(domain)
	if norm == "" {
		return false
	}
	if engine, err := c.getEngine(); err == nil {
		if dnsSrv := engine.GetDNSServer(); dnsSrv != nil && dnsSrv.MatchManagedDomain(norm) {
			return true
		}
	}
	if c.recorder != nil {
		for _, fqdn := range c.recorder.GetPeerFQDNs() {
			if normalizeDomain(fqdn) == norm {
				return true
			}
		}
	}
	return false
}

// LookupIP resolves a NetBird-managed domain directly against the embedded
// DNS server without touching the OS resolver or falling through to fallback
// upstreams. Returns (nil, 0, nil) when the domain is authoritative/managed
// but has no records of the requested IP family (NODATA).
func (c *Client) LookupIP(ctx context.Context, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error) {
	engine, err := c.getEngine()
	if err != nil {
		return nil, 0, err
	}
	dnsSrv := engine.GetDNSServer()
	if dnsSrv == nil {
		return nil, 0, fmt.Errorf("netbird dns server not initialized")
	}
	return lookupManagedIP(ctx, dnsSrv, domain, ipv4, ipv6)
}

func lookupManagedIP(ctx context.Context, dnsSrv nbdns.Server, domain string, ipv4, ipv6 bool) ([]netip.Addr, uint32, error) {
	norm := normalizeDomain(domain)
	if norm == "" || !dnsSrv.MatchManagedDomain(norm) {
		return nil, 0, fmt.Errorf("domain %q is not managed by netbird dns", domain)
	}
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
		resp, err := dnsSrv.ResolveManagedDomain(ctx, norm, qtype)
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
		return nil, 0, lastErr
	}
	return nil, 0, fmt.Errorf("netbird dns lookup for %q failed: rcode=%s", norm, miekgdns.RcodeToString[lastRcode])
}
