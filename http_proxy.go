package msocks

import (
	"bufio"
	"net"
	"net/http"

	"github.com/pkg/errors"
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

func (c *Client) serveHTTPConnect(conn net.Conn, req *http.Request) (net.Conn, error) {
	tun, err := c.connect("tcp", req.URL.Host)
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

func (c *Client) serveHTTPProxy(conn net.Conn, req *http.Request) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
