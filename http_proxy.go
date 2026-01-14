package msocks

import (
	"bufio"
	"net"
	"net/http"
)

func (c *Client) serveHTTPRequest(conn net.Conn, reader *bufio.Reader) (net.Conn, error) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	if req.Method == http.MethodConnect {
		return c.serveHTTPConnect(conn, req)
	}
	return c.serveHTTPProxy(conn, reader, req)
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

func (c *Client) serveHTTPProxy(conn net.Conn, rd *bufio.Reader, req *http.Request) (net.Conn, error) {
	badResp := http.Response{}
	badResp.StatusCode = http.StatusBadGateway
	badResp.Proto = "HTTP/1.1"
	badResp.ProtoMajor = 1
	badResp.ProtoMinor = 1

	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	address := net.JoinHostPort(req.URL.Host, port)

	tun, err := c.connect("tcp", address)
	if err != nil {
		_ = badResp.Write(conn)
		return nil, err
	}
	defer func() { _ = tun.Close() }()

	// process request loop
	tunBuf := bufio.NewReader(tun)
	for {
		err = req.Write(tun)
		if err != nil {
			_ = badResp.Write(conn)
			return nil, err
		}
		resp, err := http.ReadResponse(tunBuf, req)
		if err != nil {
			_ = badResp.Write(conn)
			return nil, err
		}
		err = resp.Write(conn)
		if err != nil {
			return nil, nil
		}
		req, err = http.ReadRequest(rd)
		if err != nil {
			return nil, nil
		}
	}
}
