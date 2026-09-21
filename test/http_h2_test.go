package main

import (
	std_bufio "bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

const proxyAuthorization = "Basic c2VrYWk6cGFzc3dvcmQ="

func startTLSHTTPInbound(t *testing.T, certPem string, keyPem string, extraOutbounds []option.Outbound) {
	outbounds := append([]option.Outbound{{Type: C.TypeDirect}}, extraOutbounds...)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeHTTP,
				Options: &option.HTTPInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: serverPort,
					},
					Users: []auth.User{{Username: "sekai", Password: "password"}},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							KeyPath:         keyPem,
						},
					},
				},
			},
		},
		Outbounds: outbounds,
	})
}

func dialHTTP2Proxy(t *testing.T, port uint16) *http2.ClientConn {
	tlsConn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         "example.org",
		InsecureSkipVerify: true,
		NextProtos:         []string{http2.NextProtoTLS},
	})
	require.NoError(t, err)
	require.Equal(t, http2.NextProtoTLS, tlsConn.ConnectionState().NegotiatedProtocol)
	clientConn, err := (&http2.Transport{}).NewClientConn(tlsConn)
	require.NoError(t, err)
	t.Cleanup(func() {
		clientConn.Close()
	})
	return clientConn
}

type http2Tunnel struct {
	writer   *io.PipeWriter
	response *http.Response
}

func openHTTP2Tunnel(t *testing.T, clientConn *http2.ClientConn, host string, authorization string) *http2Tunnel {
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: host},
		Host:   host,
		Header: make(http.Header),
		Body:   pipeReader,
	}
	if authorization != "" {
		request.Header.Set("Proxy-Authorization", authorization)
	}
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	return &http2Tunnel{writer: pipeWriter, response: response}
}

func (t *http2Tunnel) close() {
	t.writer.Close()
	t.response.Body.Close()
}

func TestHTTPInboundHTTP2(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, nil)
	origin := newForwardOrigin(t)
	clientConn := dialHTTP2Proxy(t, serverPort)

	rejected := openHTTP2Tunnel(t, clientConn, origin.host(), "")
	require.Equal(t, http.StatusProxyAuthRequired, rejected.response.StatusCode)
	require.Contains(t, rejected.response.Header.Get("Proxy-Authenticate"), "Basic")
	rejected.close()

	first := openHTTP2Tunnel(t, clientConn, origin.host(), proxyAuthorization)
	require.Equal(t, http.StatusOK, first.response.StatusCode)
	second := openHTTP2Tunnel(t, clientConn, origin.host(), proxyAuthorization)
	require.Equal(t, http.StatusOK, second.response.StatusCode)
	for _, tunnel := range []*http2Tunnel{second, first} {
		_, err := tunnel.writer.Write([]byte("GET /hello HTTP/1.1\r\nHost: " + origin.host() + "\r\n\r\n"))
		require.NoError(t, err)
		response, err := http.ReadResponse(std_bufio.NewReader(tunnel.response.Body), nil)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, "hello", string(body))
		tunnel.close()
	}

	request, err := http.NewRequest(http.MethodGet, origin.url("/hello"), nil)
	require.NoError(t, err)
	request.Header.Set("User-Agent", "")
	request.Header.Set("Proxy-Authorization", proxyAuthorization)
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "hello", string(body))
	require.Equal(t, origin.host(), response.Header.Get("X-Host"))

	response, err = clientConn.RoundTrip(request)
	require.NoError(t, err)
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))
	require.Equal(t, int32(4), origin.connections.Load())
}

type http2ProxyServer struct {
	listener    net.Listener
	connections atomic.Int32
	streams     atomic.Int32
}

func startHTTP2ProxyServer(t *testing.T, certPem string, keyPem string) *http2ProxyServer {
	certificate, err := tls.LoadX509KeyPair(certPem, keyPem)
	require.NoError(t, err)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{http2.NextProtoTLS},
	})
	require.NoError(t, err)
	server := &http2ProxyServer{listener: listener}
	h2Server := &http2.Server{}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		server.streams.Add(1)
		if request.Method != http.MethodConnect || request.Header.Get("Proxy-Authorization") != proxyAuthorization {
			writer.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		conn, err := net.Dial("tcp", request.Host)
		if err != nil {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		go func() {
			io.Copy(conn, request.Body)
			conn.(*net.TCPConn).CloseWrite()
		}()
		buffer := make([]byte, 4096)
		for {
			n, err := conn.Read(buffer)
			if n > 0 {
				_, err = writer.Write(buffer[:n])
				if err != nil {
					break
				}
				writer.(http.Flusher).Flush()
			}
			if err != nil {
				break
			}
		}
		conn.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.connections.Add(1)
			go func() {
				err = conn.(*tls.Conn).Handshake()
				if err != nil {
					conn.Close()
					return
				}
				h2Server.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
	})
	return server
}

func (s *http2ProxyServer) port() uint16 {
	return uint16(s.listener.Addr().(*net.TCPAddr).Port)
}

func TestHTTPOutboundHTTP2(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	proxyServer := startHTTP2ProxyServer(t, certPem, keyPem)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeHTTP,
				Options: &option.HTTPOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: proxyServer.port(),
					},
					Username: "sekai",
					Password: "password",
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
						},
					},
				},
			},
		},
	})
	origin := newForwardOrigin(t)
	for i := 0; i < 3; i++ {
		client := proxyClient(t, clientPort)
		request, err := http.NewRequest(http.MethodGet, origin.url("/hello"), nil)
		require.NoError(t, err)
		request.Header.Set("User-Agent", "")
		response, err := client.Do(request)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, err)
		require.Equal(t, "hello", string(body))
		client.CloseIdleConnections()
	}
	require.Equal(t, int32(1), proxyServer.connections.Load())
	require.Equal(t, int32(3), proxyServer.streams.Load())
}

func TestHTTPSelfTLS(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, nil)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeHTTP,
				Options: &option.HTTPOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: serverPort,
					},
					Username: "sekai",
					Password: "password",
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
						},
					},
				},
			},
		},
	})
	origin := newForwardOrigin(t)
	client := proxyClient(t, clientPort)
	for i := 0; i < 3; i++ {
		request, err := http.NewRequest(http.MethodGet, origin.url("/hello"), nil)
		require.NoError(t, err)
		request.Header.Set("User-Agent", "")
		response, err := client.Do(request)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, err)
		require.Equal(t, "hello", string(body))
	}
	require.Equal(t, int32(1), origin.connections.Load())
}
