package bridge

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"golang.org/x/sys/unix"
)

const (
	pfctlPath    = "/sbin/pfctl"
	routePath    = "/sbin/route"
	sysctlPath   = "/usr/sbin/sysctl"
	ifconfigPath = "/sbin/ifconfig"
)

var (
	bridgeInet4LocalBase = netip.MustParseAddr("198.51.100.1")
	bridgeInet6LocalBase = netip.MustParseAddr("2001:db8:1::1")
)

type backendDarwin struct {
	backendBase

	// anchorName lives under com.apple/* so the stock pf.conf's wildcard
	// nat/scrub/anchor references evaluate our rules without editing it.
	anchorName string

	inet4Local netip.Addr
	inet6Local netip.Addr

	writeAccess sync.Mutex
	writeBuffer []byte

	pfToken string

	currentRules string

	platform adapter.PlatformInterface
}

func newBackend(ctx context.Context, logger logger.ContextLogger, networkManager adapter.NetworkManager, tag string, options option.BridgeOutboundOptions) (Backend, error) {
	instance := &backendDarwin{
		writeBuffer: make([]byte, tun.PacketOffset+maxPacketLength),
	}
	err := instance.init(ctx, logger, networkManager, tag, options)
	if err != nil {
		return nil, err
	}
	instance.inet4Local = addressAt(bridgeInet4LocalBase, instance.index)
	instance.inet6Local = addressAt(bridgeInet6LocalBase, instance.index)
	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	if platformInterface != nil && platformInterface.UsePlatformBridge() {
		instance.platform = platformInterface
	}
	return instance, nil
}

func (b *backendDarwin) Start(stage adapter.StartStage) error {
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

func (b *backendDarwin) start() error {
	tunOptions := tun.Options{
		MTU:              bridgeTunMTU,
		AutoRoute:        false,
		InterfaceMonitor: b.networkManager.InterfaceMonitor(),
		Logger:           b.logger,
	}
	if b.platform != nil {
		tunFd, tunName, err := b.platform.CreateBridge(bridgeTunMTU)
		if err != nil {
			return E.Cause(err, "create bridge tun")
		}
		b.tunName = tunName
		tunOptions.FileDescriptor = tunFd
	} else {
		b.tunName = tun.CalculateInterfaceName(b.bridgeName)
	}
	tunOptions.Name = b.tunName
	b.anchorName = "com.apple/sing-box-" + b.tunName
	tunInterface, err := tun.New(tunOptions)
	if err != nil {
		return E.Cause(err, "create bridge tun")
	}
	b.tunInterface = tunInterface
	err = tunInterface.Start()
	if err != nil {
		return E.Cause(err, "start bridge tun")
	}
	b.setupForwarding()
	err = b.assignPortAddress(b.inet4Local, b.inet4Port)
	if err != nil {
		return E.Cause(err, "add bridge route")
	}
	err = b.assignPortAddress(b.inet6Local, b.inet6Port)
	if err != nil {
		b.logger.Debug(E.Cause(err, "IPv6 bridge routing unavailable, disabling IPv6 forwarding"))
		b.inet6Port = netip.Addr{}
	}
	err = b.enablePf()
	if err != nil {
		return E.Cause(err, "enable pf")
	}
	b.closed = make(chan struct{})
	b.readDone = make(chan struct{})
	if b.boundInterface != "" {
		monitor := b.networkManager.NetworkMonitor()
		if monitor != nil {
			element := monitor.RegisterCallback(func() { b.syncEgress() })
			b.unregister = func() { monitor.UnregisterCallback(element) }
		} else {
			b.logger.Debug("network monitor unavailable, pinned egress will not track interface changes")
		}
	} else {
		monitor := b.networkManager.InterfaceMonitor()
		if monitor != nil {
			element := monitor.RegisterCallback(func(_ *control.Interface, _ int) { b.syncEgress() })
			b.unregister = func() { monitor.UnregisterCallback(element) }
		}
	}
	b.syncEgress()
	go b.readLoop()
	b.logger.Info("bridge started at ", b.tunName, " (masquerade, egress ", b.egressLabel(), ")")
	return nil
}

func (b *backendDarwin) egressLabel() string {
	if b.boundInterface != "" {
		return b.boundInterface
	}
	return "auto"
}

func (b *backendDarwin) Close() error {
	b.closeOnce.Do(func() {
		if b.closed != nil {
			close(b.closed)
		}
		if b.unregister != nil {
			b.unregister()
		}
		if b.anchorName != "" {
			b.egressAccess.Lock()
			_, _ = b.run(pfctlPath, "-a", b.anchorName, "-F", "all")
			b.egressAccess.Unlock()
		}
		b.restoreForwarding()
		if b.pfToken != "" {
			_, _ = b.run(pfctlPath, "-X", b.pfToken)
		}
		if b.tunInterface != nil {
			b.tunInterface.Close()
		}
		if b.readDone != nil {
			<-b.readDone
		}
		releaseBridgeIndex(b.index)
	})
	return nil
}

// Zero tells the dispatcher not to clamp the TCP MSS or fragment; pf and the
// host kernel do both on the forwarding path instead (see buildAnchorRules).
func (b *backendDarwin) PortMTU() uint32 {
	return 0
}

func (b *backendDarwin) WritePackets(packets [][]byte) error {
	b.writeAccess.Lock()
	defer b.writeAccess.Unlock()
	for _, packet := range packets {
		if len(packet) == 0 || len(packet) > maxPacketLength {
			continue
		}
		ipVersion := header.IPVersion(packet)
		if ipVersion != header.IPv4Version && ipVersion != header.IPv6Version {
			continue
		}
		buffer := b.writeBuffer[:tun.PacketOffset+len(packet)]
		tun.PacketFillHeader(buffer, ipVersion)
		copy(buffer[tun.PacketOffset:], packet)
		_, err := b.tunInterface.Write(buffer)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *backendDarwin) syncEgress() {
	b.egressAccess.Lock()
	defer b.egressAccess.Unlock()
	select {
	case <-b.closed:
		return
	default:
	}
	egress := b.resolveEgress()
	if egress != "" {
		_, err := b.networkManager.InterfaceFinder().ByName(egress)
		if err != nil {
			egress = ""
		}
	}
	rules := ""
	if egress != "" {
		rules = b.buildAnchorRules(egress)
	}
	if rules == b.currentRules {
		return
	}
	err := b.loadAnchor(rules)
	if err != nil {
		b.logger.Debug(E.Cause(err, "apply bridge egress ", egress))
		return
	}
	b.currentRules = rules
	if egress == "" {
		b.logger.Debug("bridge egress unavailable, dropping forwarded traffic")
	} else {
		b.logger.Debug("bridge egress ", egress)
	}
}

func (b *backendDarwin) buildAnchorRules(egress string) string {
	mtu := b.egressMTU(egress)
	var builder strings.Builder
	if b.inet4Port.IsValid() {
		fmt.Fprintf(&builder, "scrub on %s inet proto tcp from %s to any max-mss %d\n", egress, b.inet4Port, mtu-40)
	}
	if b.inet6Port.IsValid() {
		fmt.Fprintf(&builder, "scrub on %s inet6 proto tcp from %s to any max-mss %d\n", egress, b.inet6Port, mtu-60)
	}
	if b.inet4Port.IsValid() {
		fmt.Fprintf(&builder, "nat on %s inet from %s to any -> (%s)\n", egress, b.inet4Port, egress)
	}
	if b.inet6Port.IsValid() {
		fmt.Fprintf(&builder, "nat on %s inet6 from %s to any -> (%s)\n", egress, b.inet6Port, egress)
	}
	// pf evaluates translation on the interface the routing table picks, and
	// route-to on an out rule does not re-run it on the new interface: when
	// another tun holds the default route the nat-on-egress rule never matches.
	// route-to on the in side redirects before routing, so the packet actually
	// leaves via the egress and the nat rule applies there.
	if b.inet4Port.IsValid() {
		gateway := b.egressGateway(egress, "-inet")
		if gateway != "" {
			fmt.Fprintf(&builder, "pass in on %s route-to (%s %s) inet from %s to any keep state\n", b.tunName, egress, gateway, b.inet4Port)
		} else {
			b.logger.Debug("no IPv4 gateway on ", egress, ", relying on the default route")
		}
	}
	if b.inet6Port.IsValid() {
		gateway := b.egressGateway(egress, "-inet6")
		if gateway != "" {
			fmt.Fprintf(&builder, "pass in on %s route-to (%s %s) inet6 from %s to any keep state\n", b.tunName, egress, gateway, b.inet6Port)
		} else {
			b.logger.Debug("no IPv6 gateway on ", egress, ", relying on the default route")
		}
	}
	return builder.String()
}

func (b *backendDarwin) egressGateway(egress string, family string) string {
	output, err := b.run(routePath, "-n", "get", "-ifscope", egress, family, "default")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(output, "\n") {
		after, found := strings.CutPrefix(strings.TrimSpace(line), "gateway:")
		if !found {
			continue
		}
		gateway := strings.TrimSpace(after)
		gateway, _, _ = strings.Cut(gateway, "%")
		_, err = netip.ParseAddr(gateway)
		if err != nil {
			return ""
		}
		return gateway
	}
	return ""
}

// Assigning the port as the utun's point-to-point destination makes the kernel
// install the host route itself; `route add -interface` against an address-less
// utun fails with ENETUNREACH.
func (b *backendDarwin) assignPortAddress(local netip.Addr, port netip.Addr) error {
	if !port.IsValid() {
		return nil
	}
	var (
		output string
		err    error
	)
	if port.Is4() {
		output, err = b.run(ifconfigPath, b.tunName, "inet", local.String(), port.String(), "netmask", "255.255.255.255")
	} else {
		output, err = b.run(ifconfigPath, b.tunName, "inet6", local.String(), port.String(), "prefixlen", "128")
	}
	if err != nil {
		return E.Cause(err, "ifconfig: ", strings.TrimSpace(output))
	}
	output, err = b.run(routePath, "-n", "add", familyFlag(port), "-host", port.String(), "-interface", b.tunName)
	if err != nil && !strings.Contains(output, "File exists") {
		return E.Cause(err, "route add: ", strings.TrimSpace(output))
	}
	return nil
}

func familyFlag(port netip.Addr) string {
	if port.Is6() {
		return "-inet6"
	}
	return "-inet"
}

func (b *backendDarwin) setupForwarding() {
	enable := func(name string) {
		output, err := b.run(sysctlPath, "-n", name)
		if err != nil {
			b.logger.Debug(E.Cause(err, "read ", name))
			return
		}
		value := strings.TrimSpace(output)
		if value == "1" {
			return
		}
		_, err = b.run(sysctlPath, "-w", name+"=1")
		if err != nil {
			b.logger.Debug(E.Cause(err, "enable ", name))
			return
		}
		b.forwardingRestore = append(b.forwardingRestore, sysctlState{name: name, value: value})
	}
	if b.inet4Port.IsValid() {
		enable("net.inet.ip.forwarding")
	}
	if b.inet6Port.IsValid() {
		enable("net.inet6.ip6.forwarding")
	}
}

func (b *backendDarwin) restoreForwarding() {
	for _, state := range b.forwardingRestore {
		_, _ = b.run(sysctlPath, "-w", state.name+"="+state.value)
	}
	b.forwardingRestore = nil
}

func (b *backendDarwin) enablePf() error {
	output, err := b.run(pfctlPath, "-E")
	if err != nil {
		return E.Cause(err, output)
	}
	b.pfToken = parsePfToken(output)
	return nil
}

func (b *backendDarwin) loadAnchor(rules string) error {
	output, err := b.runInput(rules, pfctlPath, "-a", b.anchorName, "-f", "-")
	if err != nil {
		return E.Cause(err, "pfctl load anchor: ", strings.TrimSpace(output))
	}
	return nil
}

func (b *backendDarwin) run(name string, args ...string) (string, error) {
	return b.runInput("", name, args...)
}

func (b *backendDarwin) runInput(stdin string, name string, args ...string) (string, error) {
	if b.platform != nil {
		return b.runShellSession(stdin, name, args)
	}
	command := exec.Command(name, args...)
	if stdin != "" {
		command.Stdin = strings.NewReader(stdin)
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func (b *backendDarwin) runShellSession(stdin string, name string, args []string) (string, error) {
	rootUser, err := b.platform.LookupUser("root")
	if err != nil {
		return "", E.Cause(err, "lookup root user")
	}
	session, err := b.platform.OpenShellSession(rootUser, shellQuoteJoin(name, args), nil, "", 0, 0)
	if err != nil {
		return "", err
	}
	defer session.Close()
	masterFd, err := unix.Dup(int(session.MasterFD()))
	if err != nil {
		return "", E.Cause(err, "dup session fd")
	}
	master := os.NewFile(uintptr(masterFd), "bridge-session")
	defer master.Close()
	if stdin != "" {
		_, err = master.WriteString(stdin)
		if err != nil {
			return "", E.Cause(err, "write session stdin")
		}
	}
	err = unix.Shutdown(masterFd, unix.SHUT_WR)
	if err != nil {
		return "", E.Cause(err, "close session stdin")
	}
	output, err := io.ReadAll(master)
	if err != nil {
		return string(output), E.Cause(err, "read session output")
	}
	status, err := session.WaitExit()
	if err != nil {
		return string(output), err
	}
	if status != 0 {
		return string(output), E.New("exit status ", status)
	}
	return string(output), nil
}

func shellQuoteJoin(name string, args []string) string {
	var builder strings.Builder
	builder.WriteString(shellQuote(name))
	for _, arg := range args {
		builder.WriteString(" ")
		builder.WriteString(shellQuote(arg))
	}
	return builder.String()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// `pfctl -E` prints the reference token on a line of the form
// "Token : 12345678901234567890".
func parsePfToken(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		after, found := strings.CutPrefix(strings.TrimSpace(line), "Token :")
		if found {
			return strings.TrimSpace(after)
		}
	}
	return ""
}
