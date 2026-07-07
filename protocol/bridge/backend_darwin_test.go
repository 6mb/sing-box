package bridge

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

type testNetworkManager struct {
	adapter.NetworkManager
	interfaceMonitor tun.DefaultInterfaceMonitor
	interfaceFinder  control.InterfaceFinder
}

func (m *testNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return m.interfaceMonitor
}

func (m *testNetworkManager) NetworkMonitor() tun.NetworkUpdateMonitor {
	return nil
}

func (m *testNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return m.interfaceFinder
}

type testReturn struct {
	packets chan []byte
}

func (r *testReturn) ReturnHeadroom() int {
	return 0
}

func (r *testReturn) ReturnPackets(packets [][]byte) [][]byte {
	for _, packet := range packets {
		select {
		case r.packets <- append([]byte{}, packet...):
		default:
		}
	}
	return nil
}

func TestBridgeForwarding(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	ctx := context.Background()
	testLogger := log.StdLogger()
	networkMonitor, err := tun.NewNetworkUpdateMonitor(testLogger)
	if err != nil {
		t.Fatal(err)
	}
	err = networkMonitor.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer networkMonitor.Close()
	interfaceFinder := control.NewDefaultInterfaceFinder()
	err = interfaceFinder.Update()
	if err != nil {
		t.Fatal(err)
	}
	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, testLogger, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = interfaceMonitor.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer interfaceMonitor.Close()
	networkManager := &testNetworkManager{
		interfaceMonitor: interfaceMonitor,
		interfaceFinder:  interfaceFinder,
	}
	backend, err := newBackend(ctx, testLogger, networkManager, "bridge-test", option.BridgeOutboundOptions{
		Interface: os.Getenv("BRIDGE_TEST_INTERFACE"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	err = backend.Start(adapter.StartStateStart)
	if err != nil {
		t.Fatal(err)
	}
	returnPath := &testReturn{packets: make(chan []byte, 16)}
	err = backend.AttachReturn(returnPath)
	if err != nil {
		t.Fatal(err)
	}
	inet4Port, _ := backend.PortAddresses()
	deadline := time.After(10 * time.Second)
	probe := time.NewTicker(time.Second)
	defer probe.Stop()
	var queryID uint16 = 0x4242
	err = backend.WritePackets([][]byte{buildTestDNSQuery(inet4Port, queryID)})
	if err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case packet := <-returnPath.packets:
			if isTestDNSReply(packet, inet4Port, queryID) {
				return
			}
		case <-probe.C:
			queryID++
			err = backend.WritePackets([][]byte{buildTestDNSQuery(inet4Port, queryID)})
			if err != nil {
				t.Fatal(err)
			}
		case <-deadline:
			t.Fatal("no DNS reply through bridge")
		}
	}
}

func buildTestDNSQuery(source netip.Addr, id uint16) []byte {
	dns := []byte{
		byte(id >> 8), byte(id), 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	udpLength := 8 + len(dns)
	packet := make([]byte, 20+udpLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:], id)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], []byte{1, 1, 1, 1})
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:], 40011)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLength))
	copy(udp[8:], dns)
	fixReturnChecksum(packet)
	return packet
}

func isTestDNSReply(packet []byte, port netip.Addr, id uint16) bool {
	if len(packet) < 20+8+2 || packet[0]>>4 != 4 || packet[9] != 17 {
		return false
	}
	if [4]byte(packet[12:16]) != [4]byte{1, 1, 1, 1} || [4]byte(packet[16:20]) != port.As4() {
		return false
	}
	udp := packet[20:]
	if binary.BigEndian.Uint16(udp[0:]) != 53 || binary.BigEndian.Uint16(udp[2:]) != 40011 {
		return false
	}
	return binary.BigEndian.Uint16(udp[8:]) == id
}
