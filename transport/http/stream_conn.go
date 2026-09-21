package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/baderror"
	N "github.com/sagernet/sing/common/network"
)

type serverStreamConn struct {
	reader     io.ReadCloser
	writer     io.Writer
	flusher    http.Flusher
	localAddr  net.Addr
	remoteAddr net.Addr
	access     sync.Mutex
	closed     bool
	done       chan struct{}
}

func newServerStreamConn(request *http.Request, writer http.ResponseWriter, remoteAddr net.Addr) *serverStreamConn {
	localAddr, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return &serverStreamConn{
		reader:     request.Body,
		writer:     writer,
		flusher:    writer.(http.Flusher),
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		done:       make(chan struct{}),
	}
}

func (c *serverStreamConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	return n, baderror.WrapH2(err)
}

func (c *serverStreamConn) Write(p []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	n, err := c.writer.Write(p)
	if err != nil {
		return n, baderror.WrapH2(err)
	}
	c.flusher.Flush()
	return n, nil
}

func (c *serverStreamConn) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.done)
	return c.reader.Close()
}

func (c *serverStreamConn) wait(ctx context.Context) {
	select {
	case <-c.done:
	case <-ctx.Done():
		c.Close()
	}
}

func (c *serverStreamConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *serverStreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *serverStreamConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverStreamConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverStreamConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *serverStreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

type clientStreamConn struct {
	reader     io.ReadCloser
	writer     *io.PipeWriter
	cancel     context.CancelFunc
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     atomic.Bool
}

func (c *clientStreamConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	return n, c.wrapError(err)
}

func (c *clientStreamConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	return n, c.wrapError(err)
}

func (c *clientStreamConn) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if c.closed.Load() || strings.Contains(err.Error(), "client connection force closed") {
		return net.ErrClosed
	}
	return baderror.WrapH2(err)
}

func (c *clientStreamConn) CloseWrite() error {
	return c.writer.Close()
}

func (c *clientStreamConn) Close() error {
	c.closed.Store(true)
	c.writer.Close()
	c.reader.Close()
	c.cancel()
	return nil
}

func (c *clientStreamConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *clientStreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *clientStreamConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *clientStreamConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *clientStreamConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *clientStreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

var (
	_ net.Conn      = (*serverStreamConn)(nil)
	_ net.Conn      = (*clientStreamConn)(nil)
	_ N.WriteCloser = (*clientStreamConn)(nil)
)
