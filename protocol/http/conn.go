package http

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

type Conn struct {
	netproxy.Conn

	proxy *HttpProxy
	addr  string

	chShakeFinished chan struct{}
	muShake         sync.Mutex
}

func NewConn(c netproxy.Conn, proxy *HttpProxy, addr string) *Conn {
	return &Conn{
		Conn:            c,
		proxy:           proxy,
		addr:            addr,
		chShakeFinished: make(chan struct{}),
	}
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.muShake.Lock()
	select {
	case <-c.chShakeFinished:
		c.muShake.Unlock()
		return c.Conn.Write(b)
	default:
		// Handshake
		defer c.muShake.Unlock()
		defer close(c.chShakeFinished)
		_, firstLine, _ := bufio.ScanLines(b, true)
		isHttpReq := regexp.MustCompile(`^\S+ \S+ HTTP/[\d.]+$`).Match(firstLine)

		var req *http.Request
		if isHttpReq {
			// HTTP Request

			req, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
			if err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) {
					// Request more data.
					return len(b), nil
				}
				// Error
				return 0, err
			}

			req.URL.Scheme = "http"
			req.URL.Host = c.addr
		} else {
			// Arbitrary TCP

			// HACK. http.ReadRequest also does this.
			reqURL, err := url.Parse("http://" + c.addr)
			if err != nil {
				return 0, err
			}
			reqURL.Scheme = ""

			req, err = http.NewRequest("CONNECT", reqURL.String(), nil)
			if err != nil {
				return 0, err
			}
		}
		req.Close = false
		if c.proxy.HaveAuth {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.proxy.Username+":"+c.proxy.Password)))
		}
		// https://www.rfc-editor.org/rfc/rfc7230#appendix-A.1.2
		// As a result, clients are encouraged not to send the Proxy-Connection header field in any requests.
		if len(req.Header.Values("Proxy-Connection")) > 0 {
			req.Header.Del("Proxy-Connection")
		}

		nextProto := ""
		if tlsConn, ok := c.Conn.(*tls.Conn); ok {
			if err := tlsConn.Handshake(); err != nil {
				return 0, err
			}
			nextProto = tlsConn.ConnectionState().NegotiatedProtocol
		}

		connectHttp1 := func() (n int, err error) {
			err = req.WriteProxy(c.Conn)
			if err != nil {
				return 0, err
			}

			if isHttpReq {
				// Allow read here to void race.
				return len(b), nil
			} else {
				// We should read tcp connection here, and we will be guaranteed higher priority by chShakeFinished.
				resp, err := http.ReadResponse(bufio.NewReader(c.Conn), req)
				if err != nil {
					if resp != nil {
						resp.Body.Close()
					}
					return 0, err
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					err = fmt.Errorf("connect server using proxy error, StatusCode [%d]", resp.StatusCode)
					return 0, err
				}
				return c.Conn.Write(b)
			}
		}

		// Thanks to v2fly/v2ray-core.
		connectHttp2 := func(h2clientConn *http2.ClientConn) (conn netproxy.Conn, n int, err error) {
			pr, pw := io.Pipe()
			req.Body = pr

			var pErr error
			var done = make(chan struct{})

			go func() {
				_, pErr = pw.Write(b)
				done <- struct{}{}
			}()

			resp, err := h2clientConn.RoundTrip(req) // nolint: bodyclose
			if err != nil {
				return nil, 0, err
			}

			<-done
			if pErr != nil {
				return nil, 0, pErr
			}

			if resp.StatusCode != http.StatusOK {
				return nil, 0, fmt.Errorf("proxy responded with non 200 code: %v", resp.Status)
			}
			return newHTTP2Conn(&netproxy.FakeNetConn{
				Conn: c.Conn,
			}, pw, resp.Body), len(b), nil
		}

		switch nextProto {
		case "", "http/1.1":
			return connectHttp1()
		case "h2":
			onceBackground.Do(func() {
				h2ConnsPool = make(map[string]*lockedList)
				go func() {
					for range time.Tick(5 * time.Second) {
						cachedH2Mutex.Lock()
						for k := range h2ConnsPool {
							h2ConnsPool[k].mu.Lock()
							for p := h2ConnsPool[k].l.Front(); p != nil; p = p.Next() {
								c := p.Value.(*http2.ClientConn)
								if c.State().Closed {
									h2ConnsPool[k].l.Remove(p)
								}
							}
							h2ConnsPool[k].mu.Unlock()
						}
						cachedH2Mutex.Unlock()
					}
				}()
			})
			cachedH2Mutex.Lock()
			cachedConns, cachedConnsFound := h2ConnsPool[c.proxy.Host]
			cachedH2Mutex.Unlock()

			if cachedConnsFound {
				cachedConns.mu.Lock()
				if cachedConns.l.Len() > 0 {
					for p := cachedConns.l.Front(); p != nil; p = p.Next() {
						conn := p.Value.(*http2.ClientConn)
						if conn.CanTakeNewRequest() {
							proxyConn, n, err := connectHttp2(conn)
							if err != nil {
								cachedConns.mu.Unlock()
								return 0, err
							}
							c.Conn = proxyConn
							cachedConns.mu.Unlock()
							return n, nil
						}
					}
				}
				cachedConns.mu.Unlock()
			}

			t := http2.Transport{}
			h2clientConn, err := t.NewClientConn(&netproxy.FakeNetConn{
				Conn: c.Conn,
			})
			if err != nil {
				return 0, err
			}

			proxyConn, n, err := connectHttp2(h2clientConn)
			if err != nil {
				return 0, err
			}

			cachedH2Mutex.Lock()
			if h2ConnsPool[c.proxy.Host] == nil {
				h2ConnsPool[c.proxy.Host] = newLockedList()
			}
			h2ConnsPool[c.proxy.Host].l.PushFront(h2clientConn)
			cachedH2Mutex.Unlock()

			c.Conn = proxyConn
			return n, nil
		default:
			return 0, fmt.Errorf("negotiated unsupported application layer protocol: %v", nextProto)
		}
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	<-c.chShakeFinished
	return c.Conn.Read(b)
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	h.in.Close()
	return h.out.Close()
}

type lockedList struct {
	l  *list.List
	mu sync.Mutex
}

func newLockedList() *lockedList {
	return &lockedList{
		l:  list.New(),
		mu: sync.Mutex{},
	}
}

var (
	cachedH2Mutex  sync.Mutex
	h2ConnsPool    map[string]*lockedList
	onceBackground sync.Once
)
