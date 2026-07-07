//go:build !darwin

package libbox

import E "github.com/sagernet/sing/common/exceptions"

func CreateBridge(mtu int32) (*Bridge, error) {
	return nil, E.New("bridge tun creation not supported on this platform")
}
