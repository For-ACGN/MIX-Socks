package msocks

import (
	"bufio"
	"io"
	"net"

	"github.com/pkg/errors"
)

// reference:
//   https://www.ietf.org/rfc/rfc1928.txt
//   https://www.ietf.org/rfc/rfc1929.txt

const (
	version5 = 0x05

	// authenticate method
	v5NotRequired         = 0x00
	v5UsernamePassword    = 0x02
	v5NoAcceptableMethods = 0xFF

	// authenticate
	v5UsernamePasswordVersion = 0x01
	v5StatusSucceeded         = 0x00
	v5StatusFailed            = 0x01

	v5Reserve   = 0x00
	v5NoReserve = 0x01

	// command
	v5Connect = 0x01

	// address type
	v5AddrTypeIPv4 = 0x01
	v5AddrTypeFQDN = 0x03
	v5AddrTypeIPv6 = 0x04

	// reply
	v5Succeeded      = 0x00
	v5ConnRefused    = 0x05
	v5CmdNotSupport  = 0x07
	v5AddrNotSupport = 0x08
)

var (
	v5ReplySucceeded      = []byte{version5, v5Succeeded, v5Reserve, v5AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	v5ReplyConnectRefused = []byte{version5, v5ConnRefused, v5Reserve, v5AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	v5ReplyAddrNotSupport = []byte{version5, v5AddrNotSupport, v5Reserve, v5AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
)

func (c *Client) serveSocks5(conn net.Conn, reader *bufio.Reader) (net.Conn, error) {
	buf := make([]byte, 4)
	// read version
	_, err := io.ReadFull(reader, buf[:1])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read socks5 version")
	}
	return nil, nil
}
