package proto

import (
	"bytes"
	"fmt"
	"github.com/mzz2017/softwind/ciphers"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pool"
	"github.com/mzz2017/softwind/protocol/shadowsocks_stream"
	"io"
	"sync"
)

type Conn struct {
	netproxy.Conn
	Protocol            IProtocol
	underPostdecryptBuf *bytes.Buffer
	readLater           io.Reader

	init       bool
	innerIvLen int
	writeMu    sync.Mutex
	readMu     sync.Mutex
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
		underPostdecryptBuf: new(bytes.Buffer),
	}, nil
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
	c.innerIvLen = len(iv)
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
	c.readMu.Lock()
	defer c.readMu.Unlock()
	// Conn Read: obfs->ss->proto
	if c.readLater != nil {
		n, _ = c.readLater.Read(b)
		if n != 0 {
			return n, nil
		}
		c.readLater = nil
	}
readAgain:
	buf := pool.Get(2048)
	defer pool.Put(buf)
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n == 0 && err == nil {
		goto readAgain
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
		c.init = true
		err = c.initEncoder(b)
		if err != nil {
			return nil, err
		}
	}

	return c.Protocol.PreEncrypt(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Conn Write: obfs<-ss<-proto
	data, err := c.encode(b)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
