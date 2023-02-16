package proto

import (
	"bytes"
	"fmt"
	"github.com/mzz2017/softwind/ciphers"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pkg/zeroalloc/buffer"
	"github.com/mzz2017/softwind/pool"
	"github.com/mzz2017/softwind/protocol/shadowsocks_stream"
	"io"
)

type Conn struct {
	netproxy.Conn
	Protocol            IProtocol
	underPostdecryptBuf *buffer.Buffer
	readLater           io.Reader

	init bool
}

func NewConn(c netproxy.Conn, proto IProtocol) (*Conn, error) {
	switch c.(type) {
	case *shadowsocks_stream.TcpConn:
	default:
		return nil, fmt.Errorf("unsupported inner Conn")
	}
	return &Conn{
		Conn:                c,
		Protocol:            proto,
		underPostdecryptBuf: new(buffer.Buffer),
	}, nil
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func (c *Conn) InnerCipher() *ciphers.StreamCipher {
	switch innerConn := c.Conn.(type) {
	case *shadowsocks_stream.TcpConn:
		return innerConn.Cipher()
	default:
		return nil
	}
}

func (c *Conn) initEncoder(b []byte) (err error) {
	iv, err := c.InnerCipher().InitEncrypt()
	if err != nil {
		return err
	}
	key := c.InnerCipher().Key()
	if key == nil {
		return fmt.Errorf("inner conn did not init Key")
	}

	protocolServerInfo := c.Protocol.GetServerInfo()
	protocolServerInfo.IV = iv
	protocolServerInfo.Key = key
	protocolServerInfo.AddrLen = len(b)
	c.Protocol.SetServerInfo(protocolServerInfo)
	c.Protocol.SetData(c.Protocol.GetData())

	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	// Conn Read: obfs->ss->proto
	if c.readLater != nil {
		n, _ = c.readLater.Read(b)
		if n != 0 {
			return n, nil
		}
		c.readLater = nil
	}

	buf := pool.Get(2048)
	defer pool.Put(buf)
	n, err = c.Conn.Read(buf)
	if n == 0 || err != nil {
		return n, err
	}

	// append buf to c.underPostdecryptBuf
	c.underPostdecryptBuf.Write(buf[:n])
	// and read it to buf immediately
	buf = c.underPostdecryptBuf.Bytes()
	postDecryptedData, length, err := c.Protocol.PostDecrypt(buf)
	if err != nil {
		c.underPostdecryptBuf.Reset()
		return 0, err
	}
	if length == 0 {
		// not enough to postDecrypt
		return 0, nil
	} else {
		c.underPostdecryptBuf.Next(length)
	}

	n = copy(b, postDecryptedData)
	if n < len(postDecryptedData) {
		c.readLater = bytes.NewReader(postDecryptedData[n:])
	}
	return n, nil
}

func (c *Conn) encode(b []byte) (outData []byte, err error) {
	if !c.init {
		err = c.initEncoder(b)
		if err != nil {
			return
		}
		c.init = true
	}

	return c.Protocol.PreEncrypt(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	// Conn Write: obfs<-ss<-proto
	data, err := c.encode(b)
	if err != nil {
		return 0, err
	}
	n, err = c.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
