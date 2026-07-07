//go:build darwin

package libbox

import (
	"os"

	"golang.org/x/sys/unix"
)

func CreateBridge(mtu int32) (*Bridge, error) {
	tunFd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	err = unix.IoctlCtlInfo(tunFd, ctlInfo)
	if err != nil {
		unix.Close(tunFd)
		return nil, os.NewSyscallError("IoctlCtlInfo", err)
	}
	err = unix.Connect(tunFd, &unix.SockaddrCtl{ID: ctlInfo.Id, Unit: 0})
	if err != nil {
		unix.Close(tunFd)
		return nil, os.NewSyscallError("Connect", err)
	}
	name, err := unix.GetsockoptString(
		tunFd,
		2, /* #define SYSPROTO_CONTROL 2 */
		2, /* #define UTUN_OPT_IFNAME 2 */
	)
	if err != nil {
		unix.Close(tunFd)
		return nil, os.NewSyscallError("GetsockoptString", err)
	}
	socketFd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		unix.Close(tunFd)
		return nil, os.NewSyscallError("socket", err)
	}
	ifr := unix.IfreqMTU{MTU: mtu}
	copy(ifr.Name[:], name)
	err = unix.IoctlSetIfreqMTU(socketFd, &ifr)
	unix.Close(socketFd)
	if err != nil {
		unix.Close(tunFd)
		return nil, os.NewSyscallError("IoctlSetIfreqMTU", err)
	}
	return &Bridge{
		FileDescriptor: int32(tunFd),
		Name:           name,
	}, nil
}
