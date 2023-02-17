package shadowsocksr

import (
	"bytes"
	"context"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/direct"
	"github.com/mzz2017/softwind/protocol/shadowsocks_stream"
	"github.com/mzz2017/softwind/transport/shadowsocksr/obfs"
	"github.com/mzz2017/softwind/transport/shadowsocksr/proto"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestTcp(t *testing.T) {
	// https://github.com/winterssy/SSR-Docker
	// Remember to set protocol_param to 3000# (max_client)
	d := direct.SymmetricDirect
	obfsDialer, err := obfs.NewDialer(d, &obfs.ObfsParam{
		ObfsHost:  "",
		ObfsPort:  0,
		Obfs:      "tls1.2_ticket_auth",
		ObfsParam: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	d = obfsDialer
	d, err = shadowsocks_stream.NewDialer(d, protocol.Header{
		ProxyAddress: "127.0.0.1:8989",
		Cipher:       "aes-256-cfb",
		Password:     "p@ssw0rd",
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	d = &proto.Dialer{
		NextDialer:    d,
		Protocol:      "auth_chain_b",
		ProtocolParam: "",
		ObfsOverhead:  obfsDialer.ObfsOverhead(),
	}

	c := http.Client{
		Transport: &http.Transport{Dial: func(network string, addr string) (net.Conn, error) {
			c, err := d.DialTcp(addr)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{
				Conn:  c,
				LAddr: nil,
				RAddr: nil,
			}, nil
		}},
	}
	resp, err := c.Get("https://www.7k7k.com")
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	t.Log(buf.String())
}

func TestUdp(t *testing.T) {
	// https://github.com/winterssy/SSR-Docker
	// Remember to set protocol_param to 3000# (max_client)
	d := direct.SymmetricDirect
	d, err := shadowsocks_stream.NewDialer(d, protocol.Header{
		ProxyAddress: "127.0.0.1:8989",
		Cipher:       "aes-256-cfb",
		Password:     "p@ssw0rd",
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		t.Fatal(err)
	}
	d = &proto.Dialer{
		NextDialer:    d,
		Protocol:      "auth_chain_b",
		ProtocolParam: "",
		ObfsOverhead:  0,
	}

	resolver := net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if !strings.HasPrefix(network, "udp") {
				return nil, fmt.Errorf("unsupported network")
			}
			c, err := d.DialUdp(address)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetPacketConn{
				PacketConn: c,
				LAddr:      nil,
				RAddr:      nil,
			}, nil
		},
	}
	ips, err := resolver.LookupNetIP(context.TODO(), "ip", "www.baidu.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ips)
}
