package bridge

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

const (
	defaultBridgeRuleIndex = 100
	// 2200 avoids sing-tun's default tun table (2022).
	defaultBridgeTableIndexBase = 2200

	bridgeWriteBatchSize = 32
)

// fullcone is an out-of-tree nftables verb (the nft_fullcone module), absent on
// stock kernels.
var (
	fullConeProbeOnce   sync.Once
	fullConeProbeResult bool
)

type backendLinux struct {
	backendBase

	nftTableName string
	routeTable   int
	ruleIndex    int

	batchTUN tun.LinuxTUN

	writeAccess   sync.Mutex
	writeHeadroom int
	writeBuffers  [][]byte

	clampMTU int
}

func newBackend(ctx context.Context, logger logger.ContextLogger, networkManager adapter.NetworkManager, tag string, options option.BridgeOutboundOptions) (Backend, error) {
	instance := &backendLinux{}
	err := instance.init(ctx, logger, networkManager, tag, options)
	if err != nil {
		return nil, err
	}
	instance.ruleIndex = options.IPRoute2RuleIndex
	if instance.ruleIndex == 0 {
		instance.ruleIndex = defaultBridgeRuleIndex
	}
	if instance.boundInterface != "" {
		instance.routeTable = options.IPRoute2TableIndex
		if instance.routeTable == 0 {
			instance.routeTable = defaultBridgeTableIndexBase + int(instance.index)
		}
	}
	return instance, nil
}

func (b *backendLinux) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := b.start()
	if err != nil {
		b.Close()
		return err
	}
	return nil
}

func (b *backendLinux) start() error {
	b.tunName = tun.CalculateInterfaceName(b.bridgeName)
	b.nftTableName = "sing-box-" + b.tunName
	tunInterface, err := tun.New(tun.Options{
		Name:             b.tunName,
		MTU:              bridgeTunMTU,
		GSO:              true,
		AutoRoute:        false,
		InterfaceMonitor: b.networkManager.InterfaceMonitor(),
		Logger:           b.logger,
	})
	if err != nil {
		return E.Cause(err, "create bridge tun")
	}
	b.tunInterface = tunInterface
	err = tunInterface.Start()
	if err != nil {
		return E.Cause(err, "start bridge tun")
	}
	linuxTUN := tunInterface.(tun.LinuxTUN)
	if linuxTUN.BatchSize() > 1 {
		b.batchTUN = linuxTUN
		b.writeHeadroom = linuxTUN.FrontHeadroom()
		b.writeBuffers = make([][]byte, bridgeWriteBatchSize)
		for i := range b.writeBuffers {
			// handleGRO coalesces same-flow packets by appending into the first
			// packet's buffer capacity, up to the 0xffff total length limit.
			b.writeBuffers[i] = make([]byte, b.writeHeadroom+maxPacketLength)
		}
	}
	b.setupForwarding()
	err = b.setupNftables()
	if err != nil {
		return E.Cause(err, "set up bridge nftables")
	}
	if b.boundInterface != "" {
		b.syncEgress()
	}
	err = b.setupFamily(unix.AF_INET, b.inet4Port)
	if err != nil {
		return E.Cause(err, "set up bridge routing")
	}
	err = b.setupFamily(unix.AF_INET6, b.inet6Port)
	if err != nil {
		b.logger.Debug(E.Cause(err, "IPv6 bridge routing unavailable, disabling IPv6 forwarding"))
		b.removeFamily(unix.AF_INET6, b.inet6Port)
		b.inet6Port = netip.Addr{}
	}
	b.closed = make(chan struct{})
	b.readDone = make(chan struct{})
	if b.batchTUN != nil {
		go b.batchReadLoop()
	} else {
		go b.readLoop()
	}
	egress := "auto"
	if b.boundInterface != "" {
		egress = b.boundInterface
		monitor := b.networkManager.NetworkMonitor()
		if monitor != nil {
			element := monitor.RegisterCallback(func() { b.syncEgress() })
			b.unregister = func() { monitor.UnregisterCallback(element) }
		} else {
			b.logger.Debug("network monitor unavailable, pinned egress will not track interface changes")
		}
		b.syncEgress()
	} else {
		monitor := b.networkManager.InterfaceMonitor()
		if monitor != nil {
			element := monitor.RegisterCallback(func(_ *control.Interface, _ int) { b.updateClamp() })
			b.unregister = func() { monitor.UnregisterCallback(element) }
		}
		b.updateClamp()
	}
	natMode := "masquerade"
	if fullConeSupported() {
		natMode = "full-cone NAT"
	}
	b.logger.Info("bridge started at ", b.tunName, " (", natMode, ", egress ", egress, ")")
	return nil
}

func (b *backendLinux) Close() error {
	b.closeOnce.Do(func() {
		if b.closed != nil {
			close(b.closed)
		}
		if b.unregister != nil {
			b.unregister()
		}
		if b.tunInterface != nil {
			b.tunInterface.Close()
		}
		if b.readDone != nil {
			<-b.readDone
		}
		b.egressAccess.Lock()
		if b.tunName != "" {
			b.cleanupNftables()
			b.removeFamily(unix.AF_INET, b.inet4Port)
			b.removeFamily(unix.AF_INET6, b.inet6Port)
		}
		if b.routeTable != 0 {
			b.flushRouteTable()
		}
		b.egressAccess.Unlock()
		b.restoreForwarding()
		releaseBridgeIndex(b.index)
	})
	return nil
}

// Zero tells the dispatcher not to clamp the TCP MSS or fragment; the host kernel
// does both on the forwarding path instead (see setupClampRules).
func (b *backendLinux) PortMTU() uint32 {
	return 0
}

func (b *backendLinux) WritePackets(packets [][]byte) error {
	if b.batchTUN == nil {
		for _, packet := range packets {
			if len(packet) == 0 {
				continue
			}
			_, err := b.tunInterface.Write(packet)
			if err != nil {
				return err
			}
		}
		return nil
	}
	b.writeAccess.Lock()
	defer b.writeAccess.Unlock()
	for len(packets) > 0 {
		chunk := packets
		if len(chunk) > len(b.writeBuffers) {
			chunk = chunk[:len(b.writeBuffers)]
		}
		packets = packets[len(chunk):]
		batch := make([][]byte, 0, len(chunk))
		for i, packet := range chunk {
			if len(packet) == 0 || len(packet) > maxPacketLength {
				continue
			}
			buffer := b.writeBuffers[i][:b.writeHeadroom+len(packet)]
			copy(buffer[b.writeHeadroom:], packet)
			batch = append(batch, buffer)
		}
		if len(batch) == 0 {
			continue
		}
		_, err := b.batchTUN.BatchWrite(batch, b.writeHeadroom)
		if err != nil {
			return err
		}
	}
	return nil
}

// BatchRead completes any kernel-deferred checksums while splitting GRO frames
// (virtio NEEDS_CSUM), so unlike readLoop no checksum fix is needed here.
func (b *backendLinux) batchReadLoop() {
	defer close(b.readDone)
	batchSize := b.batchTUN.BatchSize()
	sizes := make([]int, batchSize)
	batch := make([][]byte, 0, batchSize)
	headroom := -1
	var buffers [][]byte
	for {
		b.returnAccess.Lock()
		returnPaths := b.returnPaths
		b.returnAccess.Unlock()
		pathHeadroom := 0
		if len(returnPaths) > 0 {
			pathHeadroom = returnPaths[0].ReturnHeadroom()
		}
		if pathHeadroom != headroom {
			headroom = pathHeadroom
			buffers = make([][]byte, batchSize)
			for i := range buffers {
				buffers[i] = make([]byte, headroom+bridgeTunMTU)
			}
		}
		n, err := b.batchTUN.BatchRead(buffers, headroom, sizes)
		if err != nil {
			select {
			case <-b.closed:
				return
			default:
			}
			if E.IsClosed(err) {
				return
			}
			b.logger.Debug(E.Cause(err, "bridge tun read"))
			continue
		}
		if n == 0 || len(returnPaths) == 0 {
			continue
		}
		batch = batch[:0]
		for i := range n {
			if sizes[i] == 0 {
				continue
			}
			batch = append(batch, buffers[i][:headroom+sizes[i]])
		}
		unconsumed := batch
		currentHeadroom := headroom
		for _, returnPath := range returnPaths {
			if len(unconsumed) == 0 {
				break
			}
			nextHeadroom := returnPath.ReturnHeadroom()
			if nextHeadroom != currentHeadroom {
				rebuffered := make([][]byte, 0, len(unconsumed))
				for _, packet := range unconsumed {
					payload := packet[currentHeadroom:]
					buffer := make([]byte, nextHeadroom+len(payload))
					copy(buffer[nextHeadroom:], payload)
					rebuffered = append(rebuffered, buffer)
				}
				unconsumed = rebuffered
				currentHeadroom = nextHeadroom
			}
			unconsumed = returnPath.ReturnPackets(unconsumed)
		}
	}
}

func (b *backendLinux) setupForwarding() {
	enable := func(path string) {
		content, err := os.ReadFile(path)
		if err != nil {
			b.logger.Debug(E.Cause(err, "read ", path))
			return
		}
		value := strings.TrimSpace(string(content))
		if value == "1" {
			return
		}
		err = os.WriteFile(path, []byte("1"), 0o644)
		if err != nil {
			b.logger.Debug(E.Cause(err, "enable ", path))
			return
		}
		b.forwardingRestore = append(b.forwardingRestore, sysctlState{name: path, value: value})
	}
	if b.inet4Port.IsValid() {
		enable("/proc/sys/net/ipv4/ip_forward")
	}
	if b.inet6Port.IsValid() {
		enable("/proc/sys/net/ipv6/conf/all/forwarding")
	}
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+b.tunName+"/rp_filter", []byte("2"), 0o644)
}

func (b *backendLinux) restoreForwarding() {
	for _, state := range b.forwardingRestore {
		_ = os.WriteFile(state.name, []byte(state.value), 0o644)
	}
	b.forwardingRestore = nil
}

// The policy rules default to priority 100/101, ahead of sing-tun auto_route's rules,
// so forwarded packets egress the physical interface instead of looping back into
// a tun.
func (b *backendLinux) setupFamily(family int, port netip.Addr) error {
	if !port.IsValid() {
		return nil
	}
	link, err := netlink.LinkByName(b.tunName)
	if err != nil {
		return err
	}
	err = netlink.RouteReplace(b.familyRoute(link.Attrs().Index, family, port))
	if err != nil {
		return E.Cause(err, "add route")
	}
	for _, rule := range b.familyRules(family, port) {
		_ = netlink.RuleDel(rule)
		err = netlink.RuleAdd(rule)
		if err != nil {
			return E.Cause(err, "add rule")
		}
	}
	return nil
}

func (b *backendLinux) removeFamily(family int, port netip.Addr) {
	if !port.IsValid() {
		return
	}
	link, err := netlink.LinkByName(b.tunName)
	if err == nil {
		_ = netlink.RouteDel(b.familyRoute(link.Attrs().Index, family, port))
	}
	for _, rule := range b.familyRules(family, port) {
		_ = netlink.RuleDel(rule)
	}
}

func (b *backendLinux) familyRoute(linkIndex int, family int, port netip.Addr) *netlink.Route {
	bits := port.BitLen()
	route := &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       &net.IPNet{IP: port.AsSlice(), Mask: net.CIDRMask(bits, bits)},
		Table:     unix.RT_TABLE_MAIN,
	}
	if family == unix.AF_INET {
		route.Scope = netlink.Scope(unix.RT_SCOPE_LINK)
	}
	return route
}

func (b *backendLinux) familyRules(family int, port netip.Addr) []*netlink.Rule {
	forwardTable := unix.RT_TABLE_MAIN
	if b.routeTable != 0 {
		forwardTable = b.routeTable
	}

	iifRule := netlink.NewRule()
	iifRule.Priority = b.ruleIndex
	iifRule.IifName = b.tunName
	iifRule.Table = forwardTable
	iifRule.Family = family

	toRule := netlink.NewRule()
	toRule.Priority = b.ruleIndex + 1
	toRule.Dst = netip.PrefixFrom(port, port.BitLen())
	toRule.Table = unix.RT_TABLE_MAIN
	toRule.Family = family

	return []*netlink.Rule{iifRule, toRule}
}

func (b *backendLinux) syncEgress() {
	b.egressAccess.Lock()
	defer b.egressAccess.Unlock()
	select {
	case <-b.closed:
		return
	default:
	}
	b.updateClampLocked()
	b.flushRouteTable()
	link, err := netlink.LinkByName(b.boundInterface)
	if err != nil {
		for _, family := range b.activeFamilies() {
			b.blackholeDefault(family)
		}
		b.logger.Debug("pinned egress ", b.boundInterface, " absent, dropping forwarded traffic")
		return
	}
	for _, family := range b.activeFamilies() {
		b.syncEgressFamily(family, link.Attrs().Index)
	}
}

func (b *backendLinux) syncEgressFamily(family int, linkIndex int) {
	connected, err := netlink.RouteListFiltered(family, &netlink.Route{
		LinkIndex: linkIndex,
		Table:     unix.RT_TABLE_MAIN,
	}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err == nil {
		for _, route := range connected {
			if route.Gw != nil || route.Dst == nil {
				continue
			}
			pinned := route
			pinned.Table = b.routeTable
			pinned.ILinkIndex = 0
			_ = netlink.RouteReplace(&pinned)
		}
	}
	resolved, err := netlink.RouteGetWithOptions(probeAddress(family), &netlink.RouteGetOptions{Oif: b.boundInterface})
	if err == nil && len(resolved) > 0 {
		defaultRoute := &netlink.Route{
			LinkIndex: linkIndex,
			Table:     b.routeTable,
			Dst:       defaultDestination(family),
		}
		if len(resolved[0].Gw) > 0 {
			defaultRoute.Gw = resolved[0].Gw
		}
		err = netlink.RouteReplace(defaultRoute)
		if err == nil {
			return
		}
	}
	b.blackholeDefault(family)
}

func (b *backendLinux) blackholeDefault(family int) {
	_ = netlink.RouteReplace(&netlink.Route{
		Table:  b.routeTable,
		Family: family,
		Type:   unix.RTN_BLACKHOLE,
		Dst:    defaultDestination(family),
	})
}

func (b *backendLinux) flushRouteTable() {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: b.routeTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		for _, route := range routes {
			toDelete := route
			_ = netlink.RouteDel(&toDelete)
		}
	}
}

func (b *backendLinux) activeFamilies() []int {
	families := []int{unix.AF_INET}
	if b.inet6Port.IsValid() {
		families = append(families, unix.AF_INET6)
	}
	return families
}

func probeAddress(family int) net.IP {
	if family == unix.AF_INET6 {
		return net.ParseIP("2000::")
	}
	return net.IPv4(1, 1, 1, 1)
}

func defaultDestination(family int) *net.IPNet {
	if family == unix.AF_INET6 {
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
}

func (b *backendLinux) setupNftables() error {
	b.cleanupNftables()
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   b.nftTableName,
	})
	chain := nft.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	// The nft_fullcone verb, like masquerade, sources from the routing-chosen egress
	// interface.
	var sourceNat expr.Any = &expr.Masq{}
	if fullConeSupported() {
		sourceNat = &expr.FullCone{}
	}
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftIfname(b.tunName)},
			sourceNat,
		},
	})
	nft.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle,
	})
	return nft.Flush()
}

func (b *backendLinux) updateClamp() {
	b.egressAccess.Lock()
	defer b.egressAccess.Unlock()
	select {
	case <-b.closed:
		return
	default:
	}
	b.updateClampLocked()
}

func (b *backendLinux) updateClampLocked() {
	mtu := bridgeTunMTU
	egress := b.resolveEgress()
	if egress != "" {
		mtu = b.egressMTU(egress)
	}
	if mtu == b.clampMTU {
		return
	}
	err := b.setupClampRules(mtu)
	if err != nil {
		b.logger.Debug(E.Cause(err, "update bridge MSS clamp"))
		return
	}
	b.clampMTU = mtu
}

// nft_exthdr writes the MSS option unconditionally — unlike pf's max-mss or
// xt_TCPMSS it would also raise a smaller advertised MSS — so the rule matches
// only when the advertised MSS exceeds the clamp value.
func (b *backendLinux) setupClampRules(mtu int) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   b.nftTableName,
	}
	chain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}
	nft.FlushChain(chain)
	families := []struct {
		protocol   byte
		port       netip.Addr
		headerSize int
	}{
		{unix.NFPROTO_IPV4, b.inet4Port, 40},
		{unix.NFPROTO_IPV6, b.inet6Port, 60},
	}
	for _, family := range families {
		if !family.port.IsValid() {
			continue
		}
		clamp := binaryutil.BigEndian.PutUint16(uint16(mtu - family.headerSize))
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family.protocol}},
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftIfname(b.tunName)},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x02}, Xor: []byte{0x00}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
				&expr.Exthdr{DestRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
				&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: clamp},
				&expr.Immediate{Register: 1, Data: clamp},
				&expr.Exthdr{SourceRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
			},
		})
	}
	return nft.Flush()
}

func (b *backendLinux) cleanupNftables() {
	nft, err := nftables.New()
	if err != nil {
		return
	}
	table, err := nft.ListTableOfFamily(b.nftTableName, nftables.TableFamilyINet)
	if err != nil || table == nil {
		return
	}
	nft.DelTable(table)
	_ = nft.Flush()
}

func fullConeSupported() bool {
	fullConeProbeOnce.Do(func() {
		fullConeProbeResult = probeFullCone()
	})
	return fullConeProbeResult
}

const fullConeProbeTable = "sing-box-fullcone-probe"

// The kernel loads and validates the expression's module when the batch commits:
// a clean flush means the verb is available, a rejected one rolls back atomically.
func probeFullCone() bool {
	deleteFullConeProbe()
	nft, err := nftables.New()
	if err != nil {
		return false
	}
	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   fullConeProbeTable,
	})
	chain := nft.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftIfname("sing-box-probe0")},
			&expr.FullCone{},
		},
	})
	supported := nft.Flush() == nil
	deleteFullConeProbe()
	return supported
}

func deleteFullConeProbe() {
	nft, err := nftables.New()
	if err != nil {
		return
	}
	table, err := nft.ListTableOfFamily(fullConeProbeTable, nftables.TableFamilyINet)
	if err != nil || table == nil {
		return
	}
	nft.DelTable(table)
	_ = nft.Flush()
}

func nftIfname(name string) []byte {
	padded := make([]byte, 16)
	copy(padded, name)
	return padded
}
