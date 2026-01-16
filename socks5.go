package msocks

import (
	"bufio"
	"crypto/subtle"
	"fmt"
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
	// read authentication methods, but ignore them
	_, err = io.ReadFull(reader, buf[:1])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read the number of the authentication methods")
	}
	l := int(buf[0])
	if l == 0 {
		return nil, errors.Wrap(err, "no authentication method")
	}
	if l > len(buf) {
		buf = make([]byte, l)
	}
	_, err = io.ReadFull(reader, buf[:l])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read authentication methods")
	}
	if !c.socks5Authenticate(conn, reader) {
		return nil, errors.New("failed to authenticate")
	}
	return nil, nil
}

func (c *Client) socks5Authenticate(conn net.Conn, reader *bufio.Reader) bool {
	if c.frontUsername == "" && c.frontPassword == "" {
		_, err := conn.Write([]byte{version5, v5NotRequired})
		if err != nil {
			c.logger.Error("failed to write authentication reply:", err)
			return false
		}
		return true
	}
	_, err := conn.Write([]byte{version5, v5UsernamePassword})
	if err != nil {
		c.logger.Error("failed to write authentication methods:", err)
		return false
	}
	buf := make([]byte, 16)
	// read username and password version
	_, err = io.ReadFull(reader, buf[:1])
	if err != nil {
		c.logger.Error("failed to read username password version:", err)
		return false
	}
	if buf[0] != v5UsernamePasswordVersion {
		c.logger.Error("unexpected username password version")
		return false
	}
	// read username length
	_, err = io.ReadFull(reader, buf[:1])
	if err != nil {
		c.logger.Error("failed to read username length:", err)
		return false
	}
	l := int(buf[0])
	if l > len(buf) {
		buf = make([]byte, l)
	}
	// read username
	_, err = io.ReadFull(reader, buf[:l])
	if err != nil {
		c.logger.Error("failed to read username:", err)
		return false
	}
	username := make([]byte, l)
	copy(username, buf[:l])
	// read password length
	_, err = io.ReadFull(reader, buf[:1])
	if err != nil {
		c.logger.Error("failed to read password length:", err)
		return false
	}
	l = int(buf[0])
	if l > len(buf) {
		buf = make([]byte, l)
	}
	// read password
	_, err = io.ReadFull(reader, buf[:l])
	if err != nil {
		c.logger.Error("failed to read password:", err)
		return false
	}
	password := make([]byte, l)
	copy(password, buf[:l])
	// write username password version
	_, err = conn.Write([]byte{v5UsernamePasswordVersion})
	if err != nil {
		c.logger.Error("failed to write username password version:", err)
		return false
	}
	// compare username and password
	eUser := []byte(c.frontUsername)
	ePass := []byte(c.frontPassword)
	userErr := subtle.ConstantTimeCompare(username, eUser) != 1
	passErr := subtle.ConstantTimeCompare(password, ePass) != 1
	if userErr || passErr {
		userInfo := fmt.Sprintf("%s:%s", username, password)
		c.logger.Warning("invalid username or password:", userInfo)
		_, _ = conn.Write([]byte{v5StatusFailed})
		return false
	}
	_, err = conn.Write([]byte{v5StatusSucceeded})
	if err != nil {
		c.logger.Error("failed to write authentication reply:", err)
		return false
	}
	return true
}
