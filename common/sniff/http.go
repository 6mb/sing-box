package sniff

import (
	std_bufio "bufio"
	"context"
	"errors"
	"io"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	sHTTP "github.com/sagernet/sing-box/transport/http"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func HTTPHost(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	request, err := sHTTP.ReadRequest(std_bufio.NewReader(reader))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return E.Cause1(ErrNeedMoreData, err)
		} else {
			return err
		}
	}
	metadata.Protocol = C.ProtocolHTTP
	metadata.Domain = M.ParseSocksaddr(request.Host).AddrString()
	return nil
}
