package http

import (
	std_bufio "bufio"
	"context"
	"io"
	"maps"
	"net"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"

	"golang.org/x/net/http2"
)

const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func (r *Reader) isHTTP2Preface() (bool, error) {
	head, err := r.Peek(3)
	if err != nil {
		return false, err
	}
	if string(head) != http2Preface[:3] {
		return false, nil
	}
	preface, err := r.Peek(len(http2Preface))
	if err != nil {
		return false, err
	}
	return string(preface) == http2Preface, nil
}

func (s *Server) serveHTTP2(ctx context.Context, conn net.Conn, reader *Reader, handler Handler, source M.Socksaddr, onClose N.CloseHandlerFunc) {
	s.http2Server.ServeConn(reader.cachedConn(conn), &http2.ServeConnOpts{
		Context: ctx,
		BaseConfig: &http.Server{
			MaxHeaderBytes: maxHeaderBytes,
		},
		Handler: &httpHandler{
			server:  s,
			handler: handler,
			source:  source,
		},
	})
	if onClose != nil {
		onClose(nil)
	}
}

type httpHandler struct {
	server  *Server
	handler Handler
	source  M.Socksaddr
}

func (h *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	connectionSource := h.source
	if !connectionSource.IsValid() {
		connectionSource = M.ParseSocksaddr(request.RemoteAddr).Unwrap()
	}
	if h.server.authenticator != nil {
		username, password, ok := ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
		if !ok || !h.server.authenticator.Verify(username, password) {
			var authErr error
			if !ok {
				authErr = E.New("authentication failed: missing or malformed Proxy-Authorization")
			} else {
				authErr = E.New("authentication failed: username=", username)
			}
			h.server.logger.ErrorContext(ctx, E.Cause(authErr, "process connection from ", connectionSource))
			writer.Header().Set("Proxy-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
			writer.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		ctx = auth.ContextWithUser(ctx, username)
	}
	source := forwardedSource(request, connectionSource)
	if request.Method == http.MethodConnect {
		protocol := request.Header.Get(":protocol")
		if protocol == "" && request.ProtoMajor == 3 && !strings.HasPrefix(request.Proto, "HTTP/") {
			protocol = request.Proto
		}
		switch {
		case protocol == "":
			h.serveConnect(ctx, writer, request, source)
		case protocol == connectUDPProtocol && h.server.udp:
			h.serveConnectUDP(ctx, writer, request, source)
		default:
			h.server.logger.ErrorContext(ctx, "process connection from ", source, ": unsupported CONNECT protocol: ", protocol)
			writer.WriteHeader(http.StatusNotImplemented)
		}
		return
	}
	h.serveForward(ctx, writer, request, source)
}

func (h *httpHandler) serveConnect(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	destination := connectDestination(request)
	if !destination.IsValid() {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": invalid CONNECT target: ", request.Host)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
	conn := newServerStreamConn(request, writer, source)
	h.handler.NewConnectionEx(ctx, conn, source, destination, nil)
	conn.wait(request.Context())
}

func (h *httpHandler) serveForward(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	destination := parseAuthority(request.Host, 80)
	if request.Host == "" || !destination.IsValid() {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": invalid forward target: ", request.Host)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	removeHopByHopHeaders(request.Header)
	if _, loaded := request.Header["User-Agent"]; !loaded {
		request.Header["User-Agent"] = nil
	}
	if request.ContentLength == 0 {
		request.Body = http.NoBody
	}
	request.Close = false

	upstream := newUpstreamConn(ctx, h.handler, source, destination)
	defer upstream.Close()
	stop := context.AfterFunc(request.Context(), func() {
		upstream.Close()
	})
	defer stop()
	writeDone := make(chan error, 1)
	go func() {
		err := request.Write(upstream)
		if err != nil {
			upstream.Close()
		}
		writeDone <- err
	}()
	defer func() {
		request.Body.Close()
		<-writeDone
	}()

	var response *http.Response
	for {
		var err error
		response, err = http.ReadResponse(upstream.reader, request)
		if err != nil {
			upstream.Close()
			h.server.logger.ErrorContext(ctx, E.Cause(E.Errors(upstream.closeErr(), err), "process connection from ", source, ": read upstream response"))
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		if response.StatusCode >= 200 {
			break
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			upstream.Close()
			h.server.logger.ErrorContext(ctx, "process connection from ", source, ": unexpected 101 response")
			return
		}
		removeHopByHopHeaders(response.Header)
		copyHeader(writer.Header(), response.Header)
		writer.WriteHeader(response.StatusCode)
		clear(writer.Header())
	}
	removeHopByHopHeaders(response.Header)
	copyHeader(writer.Header(), response.Header)
	if !responseHasBody(request, response) {
		writer.Header().Del("Content-Length")
	}
	writer.WriteHeader(response.StatusCode)
	if !responseHasBody(request, response) {
		response.Body.Close()
		return
	}
	_, err := io.Copy(flushWriter{writer}, response.Body)
	response.Body.Close()
	if err != nil {
		upstream.Close()
		h.server.logger.DebugContext(ctx, "process connection from ", source, ": relay response: ", err)
	}
}

func newUpstreamConn(ctx context.Context, handler Handler, source M.Socksaddr, destination M.Socksaddr) *upstreamConn {
	serverSide, clientSide := pipe.Pipe()
	upstream := &upstreamConn{
		Conn:        clientSide,
		reader:      std_bufio.NewReader(clientSide),
		source:      source,
		destination: destination,
		done:        make(chan struct{}),
	}
	go handler.NewConnectionEx(ctx, serverSide, source, destination, N.OnceClose(func(it error) {
		upstream.err = it
		close(upstream.done)
	}))
	return upstream
}

func copyHeader(destination http.Header, source http.Header) {
	maps.Copy(destination, source)
}

type flushWriter struct {
	http.ResponseWriter
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		return n, err
	}
	w.ResponseWriter.(http.Flusher).Flush()
	return n, nil
}
