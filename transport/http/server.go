package http

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

const (
	maxHeaderBytes      = 1 << 20
	idleTimeout         = 60 * time.Second
	maxDiscardBodyBytes = 256 << 10
	discardBodyTimeout  = 5 * time.Second
	realm               = "sing-box"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type ServerOptions struct {
	Authenticator *auth.Authenticator
	Logger        logger.ContextLogger
	HTTP2         bool
	UDP           bool
}

type Server struct {
	authenticator *auth.Authenticator
	logger        logger.ContextLogger
	http2Server   *http2.Server
	udp           bool
}

func NewServer(options ServerOptions) *Server {
	server := &Server{
		authenticator: options.Authenticator,
		logger:        options.Logger,
		udp:           options.UDP,
	}
	if options.HTTP2 {
		server.http2Server = &http2.Server{
			IdleTimeout: idleTimeout,
		}
	}
	return server
}

func (s *Server) ServeConnection(ctx context.Context, conn net.Conn, reader *Reader, handler Handler, source M.Socksaddr, onClose N.CloseHandlerFunc) {
	if s.http2Server != nil {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		isHTTP2, err := reader.isHTTP2Preface()
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			s.finishConnection(ctx, conn, source, onClose, E.Cause(err, "peek request"))
			return
		}
		if isHTTP2 {
			s.serveHTTP2(ctx, conn, reader, handler, source, onClose)
			return
		}
	}
	connection := &serverConn{
		server:  s,
		ctx:     ctx,
		conn:    conn,
		reader:  reader,
		handler: handler,
		source:  source,
		onClose: onClose,
	}
	connection.serve()
}

func (s *Server) HTTP3Handler(handler Handler) http.Handler {
	return &httpHandler{
		server:  s,
		handler: handler,
	}
}

func (s *Server) finishConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc, err error) {
	conn.Close()
	if err != nil {
		if E.IsClosedOrCanceled(err) || isTimeout(err) {
			s.logger.DebugContext(ctx, "connection closed: ", err)
			err = nil
		} else {
			s.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", source))
		}
	}
	if onClose != nil {
		onClose(err)
	}
}
