package shadowsocks_stream

import (
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/ciphers"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pool"
)

// TcpConn the struct that override the netproxy.Conn methods
type TcpConn struct {
	netproxy.Conn
	cipher *ciphers.StreamCipher

	init bool
}

func NewTcpConn(c netproxy.Conn, cipher *ciphers.StreamCipher) *TcpConn {
	return &TcpConn{
		Conn:   c,
		cipher: cipher,
	}
}

func (c *TcpConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	if !c.cipher.DecryptInited() {
		if n < c.cipher.InfoIVLen() {
			return 0, errors.New(fmt.Sprintf("invalid ivLen:%v, actual length:%v", c.cipher.InfoIVLen(), n))
		}
		iv := b[:c.cipher.InfoIVLen()]
		if err = c.cipher.InitDecrypt(iv); err != nil {
			return 0, err
		}

		if c.cipher.IV() == nil {
			c.cipher.SetIV(iv)
		}
		infoIVLen := c.cipher.InfoIVLen()
		if n == c.cipher.InfoIVLen() {
			return 0, nil
		}
		c.cipher.Decrypt(b[infoIVLen:n], b[infoIVLen:n])
		n = copy(b, b[infoIVLen:n])
	} else {
		c.cipher.Decrypt(b[:n], b[:n])
	}
	return n, nil
}

func (c *TcpConn) Write(b []byte) (n int, err error) {
	lenToWrite := len(b)
	ivLen := 0
	if !c.cipher.EncryptInited() {
		_, err = c.cipher.InitEncrypt()
		if err != nil {
			return 0, err
		}
	}
	if !c.init {
		c.init = true
		iv := c.cipher.IV()
		buf := pool.Get(len(b) + len(iv))
		defer pool.Put(buf)
		ivLen = len(iv)
		copy(buf, iv)
		copy(buf[ivLen:], b)
		b = buf

		// For SSR obfs.
		if innerConn, ok := c.Conn.(interface {
			SetCipher(cipher *ciphers.StreamCipher)
		}); ok {
			innerConn.SetCipher(c.cipher)
		}
		if innerConn, ok := c.Conn.(interface {
			SetAddrLen(addrLen int)
		}); ok {
			innerConn.SetAddrLen(lenToWrite)
		}
	}
	c.cipher.Encrypt(b[ivLen:], b[ivLen:])
	if err != nil {
		return 0, err
	}
	n, err = c.Conn.Write(b)
	if err != nil {
		return 0, err
	}
	return lenToWrite, nil
}

func (c *TcpConn) Cipher() *ciphers.StreamCipher {
	return c.cipher
}
