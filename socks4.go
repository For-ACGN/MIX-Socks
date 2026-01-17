package msocks

import (
	"bufio"
	"crypto/subtle"
	"io"
	"net"

	"github.com/pkg/errors"
)

// reference:
//   http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
//   http://www.openssh.com/txt/socks4a.protocol

const (
	version4    = 0x04
	v4Connect   = 0x01
	v4Succeeded = 0x5A
	v4Refused   = 0x5B
	v4Ident     = 0x5C
	v4InvalidID = 0x5D
)

func (c *Client) serveSOCKS4(conn net.Conn, reader *bufio.Reader) (net.Conn, error) {
	// 10 = version(1) + cmd(1) + port(2) + address(4) + 2 x NULL(2) maybe
	// 16 = domain name
	buf := make([]byte, 10+16) // prepare
	_, err := io.ReadFull(reader, buf[:8])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read socks4 request")
	}
	// check version
	if buf[0] != version4 {
		c.logger.Error("")
		return nil, errors.New("unexpected socks4 version")
	}
	// command
	if buf[1] != v4Connect {
		return nil, errors.Errorf("unknown command: %d", buf[1])
	}
	if !c.checkUserID(reader) {
		return nil, errors.New("failed to check user id")
	}
	return nil, nil
}

func (c *Client) checkUserID(reader *bufio.Reader) bool {
	var userID []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			c.logger.Error("failed to read user id:", err)
			return false
		}
		// find 0x00(end)
		if b == 0x00 {
			break
		}
		userID = append(userID, b)
	}
	// compare user id
	if c.frontUsername == "" {
		return true
	}
	uid := []byte(c.frontUsername)
	if subtle.ConstantTimeCompare(uid, userID) != 1 {
		c.logger.Error("invalid user id: %s", userID)
		return false
	}
	return true
}
