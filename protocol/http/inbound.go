package http

import (
	"context"
	"io"
	"net"
	std_http "net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var ConfigureHTTP3ListenerFunc func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler std_http.Handler, tlsConfig tls.ServerConfig) (io.Closer, error)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.HTTPInboundOptions](registry, C.TypeHTTP, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           log.ContextLogger
	listener         *listener.Listener
	server           *http.Server
	tlsConfig        tls.ServerConfig
	network          []string
	networkIsDefault bool
	alpnIsDefault    bool
	http3Server      io.Closer
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeHTTP, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		server: http.NewServer(http.ServerOptions{
			Authenticator: auth.NewAuthenticator(options.Users),
			Logger:        logger,
			HTTP2:         true,
			UDP:           true,
		}),
		network:          options.Network.Build(),
		networkIsDefault: options.Network == "",
	}
	if common.Contains(inbound.network, N.NetworkUDP) && !inbound.networkIsDefault && (options.TLS == nil || !options.TLS.Enabled) {
		return nil, E.New("TLS is required for HTTP/3")
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context:        ctx,
			Logger:         logger,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: true,
		})
		if err != nil {
			return nil, err
		}
		if tlsConfig != nil && len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
			inbound.alpnIsDefault = true
		}
		inbound.tlsConfig = tlsConfig
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
		SetSystemProxy:    options.SetSystemProxy,
		SystemProxySOCKS:  false,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	err := h.listener.Start()
	if err != nil {
		return err
	}
	if h.tlsConfig != nil && common.Contains(h.network, N.NetworkUDP) {
		err = h.startHTTP3()
		if err != nil {
			if !h.networkIsDefault {
				return err
			}
			h.logger.Warn(E.Cause(err, "HTTP/3 disabled"))
		}
	}
	return nil
}

func (h *Inbound) startHTTP3() error {
	if ConfigureHTTP3ListenerFunc == nil {
		return C.ErrQUICNotIncluded
	}
	if h.alpnIsDefault {
		h.tlsConfig.SetNextProtos(append(h.tlsConfig.NextProtos(), "h3"))
	}
	var metadata adapter.InboundContext
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	http3Server, err := ConfigureHTTP3ListenerFunc(h.ctx, h.logger, h.listener, h.server.HTTP3Handler(adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.streamUserPacketConnection)), h.tlsConfig)
	if err != nil {
		return err
	}
	h.http3Server = http3Server
	return nil
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.http3Server,
		h.tlsConfig,
	)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	h.server.ServeConnection(ctx, conn, http.NewReader(conn), adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.streamUserPacketConnection), metadata.Source, onClose)
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) streamUserPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
		h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
