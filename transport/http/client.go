package http

import (
	std_bufio "bufio"
	"context"
	"encoding/base64"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
)

type tlsDialer interface {
	DialTLSContext(ctx context.Context, destination M.Socksaddr) (aTLS.Conn, error)
}

type ClientOptions struct {
	Dialer   N.Dialer
	Server   M.Socksaddr
	Username string
	Password string
	Path     string
	Headers  http.Header
}

type Client struct {
	dialer           N.Dialer
	tlsDialer        tlsDialer
	server           M.Socksaddr
	authorization    string
	host             string
	path             string
	headers          http.Header
	http2Transport   *http2.Transport
	http2Access      sync.Mutex
	http2Conn        *http2.ClientConn
	http2Unsupported atomic.Bool
}

func NewClient(options ClientOptions) (*Client, error) {
	client := &Client{
		dialer:  options.Dialer,
		server:  options.Server,
		path:    options.Path,
		headers: options.Headers.Clone(),
	}
	if client.dialer == nil {
		client.dialer = N.SystemDialer
	}
	if dialer, isTLSDialer := options.Dialer.(tlsDialer); isTLSDialer {
		client.tlsDialer = dialer
		client.http2Transport = &http2.Transport{
			DisableCompression: true,
			IdleConnTimeout:    idleTimeout,
		}
	}
	if client.headers != nil {
		client.host = client.headers.Get("Host")
		client.headers.Del("Host")
	}
	if client.host != "" && client.path != "" {
		return nil, E.New("Host header and path are not allowed at the same time")
	}
	if options.Username != "" {
		client.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password))
	}
	return client, nil
}

func (c *Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
	case N.NetworkUDP:
		return nil, os.ErrInvalid
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if c.tlsDialer != nil && !c.http2Unsupported.Load() {
		clientConn, conn, err := c.acquireHTTP2(ctx)
		if err != nil {
			return nil, err
		}
		if clientConn != nil {
			return c.connectHTTP2(ctx, clientConn, destination)
		}
		return c.connectAndClose(ctx, conn, destination)
	}
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	return c.connectAndClose(ctx, conn, destination)
}

func (c *Client) connect(ctx context.Context, conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	if ctx.Done() != nil {
		stop := context.AfterFunc(ctx, func() {
			conn.Close()
		})
		defer stop()
	}
	request := &http.Request{
		Method: http.MethodConnect,
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}
	if c.host != "" && c.host != destination.Fqdn {
		request.Host = c.host
		request.URL = &url.URL{Opaque: destination.String()}
	} else {
		request.URL = &url.URL{Host: destination.String()}
	}
	if c.path != "" {
		err := URLSetPath(request.URL, c.path)
		if err != nil {
			return nil, err
		}
	}
	maps.Copy(request.Header, c.headers)
	if _, loaded := request.Header["User-Agent"]; !loaded {
		request.Header["User-Agent"] = nil
	}
	if c.authorization != "" {
		request.Header.Set("Proxy-Authorization", c.authorization)
	}
	err := request.Write(conn)
	if err != nil {
		return nil, E.Cause(err, "write request")
	}
	reader := std_bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, E.Cause(err, "read response")
	}
	if response.StatusCode != http.StatusOK {
		return nil, statusError(response)
	}
	if reader.Buffered() > 0 {
		buffer := buf.NewSize(reader.Buffered())
		_, err = buffer.ReadFullFrom(reader, buffer.FreeLen())
		if err != nil {
			buffer.Release()
			return nil, err
		}
		return bufio.NewCachedConn(conn, buffer), nil
	}
	return conn, nil
}

func (c *Client) Close() error {
	c.http2Access.Lock()
	defer c.http2Access.Unlock()
	if c.http2Conn != nil {
		c.http2Conn.Close()
		c.http2Conn = nil
	}
	return nil
}

func statusError(response *http.Response) error {
	switch response.StatusCode {
	case http.StatusProxyAuthRequired:
		return E.New("authentication required")
	case http.StatusMethodNotAllowed:
		return E.New("method not allowed")
	default:
		return E.New("unexpected status: ", response.Status)
	}
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, err := c.listenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return bufio.NewNetPacketConn(packetConn), nil
}

func (c *Client) listenPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	if c.tlsDialer != nil && !c.http2Unsupported.Load() {
		clientConn, conn, err := c.acquireHTTP2(ctx)
		if err != nil {
			return nil, err
		}
		if clientConn != nil {
			return c.connectUDPHTTP2(ctx, clientConn, destination)
		}
		return c.connectUDPHTTP1AndClose(ctx, conn, destination)
	}
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	return c.connectUDPHTTP1AndClose(ctx, conn, destination)
}

func (c *Client) connectUDPHTTP1AndClose(ctx context.Context, conn net.Conn, destination M.Socksaddr) (N.PacketConn, error) {
	packetConn, err := c.connectUDPHTTP1(ctx, conn, destination)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return packetConn, nil
}

var _ N.Dialer = (*Client)(nil)
