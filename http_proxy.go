package msocks

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"time"
)

func (c *Client) serveHTTPRequest(conn net.Conn, reader *bufio.Reader) (net.Conn, error) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	if req.Method == http.MethodConnect {
		return c.serveHTTPConnect(conn, req)
	}
	return c.serveHTTPProxy(conn, req)
}

func (c *Client) serveHTTPConnect(conn net.Conn, r *http.Request) (net.Conn, error) {
	tun, err := c.connect("tcp", r.URL.Host)
	if err != nil {
		resp := http.Response{}
		resp.StatusCode = http.StatusBadGateway
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
		_ = resp.Write(conn)
		return nil, err
	}
	var success bool
	defer func() {
		if !success {
			_ = tun.Close()
		}
	}()
	_, err = conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		return nil, err
	}
	success = true
	return tun, nil
}

func (c *Client) serveHTTPProxy(conn net.Conn, r *http.Request) (net.Conn, error) {
	resp := http.Response{}
	resp.StatusCode = http.StatusBadGateway
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1

	port := r.URL.Port()
	if port == "" {
		port = "80"
	}
	address := net.JoinHostPort(r.URL.Host, port)
	tun, err := c.connect("tcp", address)
	if err != nil {
		_ = resp.Write(conn)
		return nil, err
	}
	defer func() { _ = tun.Close() }()

	r.Close = true
	err = r.Write(tun)
	if err != nil {
		_ = resp.Write(conn)
		return nil, err
	}

	_ = tun.SetDeadline(time.Time{})
	_, _ = io.Copy(conn, tun)
	return nil, nil
}
