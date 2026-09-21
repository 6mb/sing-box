package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/net/http2"
)

type http2ClientConn = http2.ClientConn

func (c *Client) acquireHTTP2(ctx context.Context) (*http2ClientConn, net.Conn, error) {
	c.http2Access.Lock()
	defer c.http2Access.Unlock()
	clientConn := c.http2Conn
	if clientConn != nil && clientConn.ReserveNewRequest() {
		return clientConn, nil, nil
	}
	conn, err := c.tlsDialer.DialTLSContext(ctx, c.server)
	if err != nil {
		return nil, nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
		c.http2Unsupported.Store(true)
		return nil, conn, nil
	}
	clientConn, err = c.http2Transport.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, nil, E.Cause(err, "create HTTP/2 connection")
	}
	clientConn.ReserveNewRequest()
	c.http2Conn = clientConn
	return clientConn, nil, nil
}

func (c *Client) connectHTTP2(ctx context.Context, clientConn *http2ClientConn, destination M.Socksaddr) (net.Conn, error) {
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination.String()},
		Host:   destination.String(),
		Header: c.headers.Clone(),
	}
	return c.roundTripHTTP2(ctx, clientConn, request, destination)
}

func (c *Client) roundTripHTTP2(ctx context.Context, clientConn *http2ClientConn, request *http.Request, destination M.Socksaddr) (*clientStreamConn, error) {
	pipeReader, pipeWriter := io.Pipe()
	streamCtx, cancel := context.WithCancel(context.Background())
	request.Body = pipeReader
	request = request.WithContext(streamCtx)
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	if _, loaded := request.Header["User-Agent"]; !loaded {
		request.Header["User-Agent"] = nil
	}
	if c.authorization != "" {
		request.Header.Set("Proxy-Authorization", c.authorization)
	}
	stop := context.AfterFunc(ctx, cancel)
	response, err := clientConn.RoundTrip(request)
	stop()
	if err != nil {
		cancel()
		pipeWriter.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, E.Cause(err, "HTTP/2 CONNECT")
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cancel()
		pipeWriter.Close()
		return nil, statusError(response)
	}
	return &clientStreamConn{
		reader:     response.Body,
		writer:     pipeWriter,
		cancel:     cancel,
		localAddr:  M.Socksaddr{},
		remoteAddr: destination,
	}, nil
}

func (c *Client) connectAndClose(ctx context.Context, conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	result, err := c.connect(ctx, conn, destination)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return result, nil
}
