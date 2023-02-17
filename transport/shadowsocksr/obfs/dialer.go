package obfs

import (
	"errors"
	"github.com/mzz2017/softwind/netproxy"
)

type Dialer struct {
	NextDialer netproxy.Dialer
	param      *ObfsParam

	constructor *constructor
}
type ObfsParam struct {
	ObfsHost  string
	ObfsPort  uint16
	Obfs      string
	ObfsParam string
}

func NewDialer(nextDialer netproxy.Dialer, param *ObfsParam) (*Dialer, error) {

	constructor := NewObfs(param.Obfs)
	if constructor == nil {
		return nil, errors.New("unsupported protocol type: " + param.Obfs)
	}

	d := &Dialer{
		NextDialer:  nextDialer,
		param:       param,
		constructor: constructor,
	}
	return d, nil
}

func (d *Dialer) ObfsOverhead() int {
	return d.constructor.Overhead
}

func (d *Dialer) DialTcp(address string) (netproxy.Conn, error) {
	conn, err := d.NextDialer.DialTcp(address)
	if err != nil {
		return nil, err
	}
	obfs := d.constructor.New()
	if obfs == nil {
		return nil, errors.New("unsupported protocol type: " + d.param.Obfs)
	}
	obfsServerInfo := &ServerInfo{
		Host:  d.param.ObfsHost,
		Port:  d.param.ObfsPort,
		Param: d.param.ObfsParam,
	}
	obfs.SetData(obfs.GetData())
	obfs.SetServerInfo(obfsServerInfo)

	return NewConn(conn, obfs)
}

func (d *Dialer) DialUdp(address string) (netproxy.PacketConn, error) {
	return d.NextDialer.DialUdp(address)
}
