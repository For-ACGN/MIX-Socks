package msocks

import (
	"bufio"
	"io"
	"net"

	"github.com/pkg/errors"
)

// reference:
//   http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
//   http://www.openssh.com/txt/socks4a.protocol

const (
	version4    = 0x04
	v4Succeeded = 0x5A
	v4Refused   = 0x5B
	v4Ident     = 0x5C
	v4InvalidID = 0x5D
)

func (c *Client) serveSOCKS4(conn net.Conn, reader *bufio.Reader) (net.Conn, error) {
	// 10 = version(1) + cmd(1) + port(2) + address(4) + 2xNULL(2) maybe
	// 16 = domain name
	buf := make([]byte, 10+16) // prepare
	_, err := io.ReadFull(reader, buf[:8])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read socks4 request")
	}
	return nil, nil
}
