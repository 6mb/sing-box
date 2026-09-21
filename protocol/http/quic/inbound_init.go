//go:build with_quic

package quic

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	boxHTTP "github.com/sagernet/sing-box/protocol/http"
	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

func init() {
	boxHTTP.ConfigureHTTP3ListenerFunc = func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig) (io.Closer, error) {
		err := qtls.ConfigureHTTP3(tlsConfig)
		if err != nil {
			return nil, err
		}
		udpConn, err := listener.ListenUDP()
		if err != nil {
			return nil, err
		}
		quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, &quic.Config{
			MaxIncomingStreams: 1 << 60,
			Allow0RTT:          true,
			DisablePathManager: true,
			EnableDatagrams:    true,
		})
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		http3Server := &http3.Server{
			Handler:         handler,
			EnableDatagrams: true,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard))
				return log.ContextWithNewID(ctx)
			},
		}
		go func() {
			serveErr := http3Server.ServeListener(quicListener)
			udpConn.Close()
			if serveErr != nil && !E.IsClosedOrCanceled(serveErr) {
				logger.Error("http3 server closed: ", serveErr)
			}
		}()
		return quicListener, nil
	}
	transportHTTP.HTTP3StreamFunc = func(writer http.ResponseWriter) (transportHTTP.DatagramStream, bool) {
		streamer, isStreamer := writer.(http3.HTTPStreamer)
		if !isStreamer {
			return nil, false
		}
		stream := &datagramStream{datagramsEnabled: true}
		if settingser, isSettingser := writer.(http3.Settingser); isSettingser {
			select {
			case <-settingser.ReceivedSettings():
				stream.datagramsEnabled = settingser.Settings().EnableDatagrams
			default:
			}
		}
		stream.Stream = streamer.HTTPStream()
		return stream, true
	}
}

type datagramStream struct {
	*http3.Stream
	datagramsEnabled bool
}

func (s *datagramStream) SendDatagram(payload []byte) error {
	if !s.datagramsEnabled {
		return transportHTTP.ErrDatagramUnsupported
	}
	err := s.Stream.SendDatagram(payload)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return transportHTTP.ErrDatagramUnsupported
	}
	return err
}

func (s *datagramStream) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}
