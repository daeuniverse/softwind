package shadowsocks

import (
	"crypto/sha1"
	"fmt"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/mzz2017/softwind/pool"
	"golang.org/x/crypto/hkdf"
	"io"
	"net/http"
	"sync"
)

type (
	SaltGeneratorType int
)

const (
	IodizedSaltGeneratorType SaltGeneratorType = iota
	RandomSaltGeneratorType
)

var DefaultSaltGeneratorType = IodizedSaltGeneratorType

func GetSaltGenerator(masterKey []byte, saltLen int) (sg SaltGenerator, err error) {
	MuGenerators.Lock()
	sg, ok := SaltGenerators[saltLen]
	if !ok {
		MuGenerators.Unlock()
		switch DefaultSaltGeneratorType {
		case IodizedSaltGeneratorType:
			sg, err = NewIodizedSaltGenerator(masterKey, saltLen, DefaultBucketSize, true)
			if err != nil {
				return nil, err
			}
		case RandomSaltGeneratorType:
			sg, err = NewRandomSaltGenerator(DefaultBucketSize, true)
			if err != nil {
				return nil, err
			}
		}
		MuGenerators.Lock()
		SaltGenerators[saltLen] = sg
		MuGenerators.Unlock()
	} else {
		MuGenerators.Unlock()
	}
	return sg, nil
}

const DefaultBucketSize = 300

var (
	SaltGenerators = make(map[int]SaltGenerator)
	MuGenerators   sync.Mutex
)

type SaltGenerator interface {
	Get() []byte
	Close() error
}

type IodizedSaltGenerator struct {
	tokenBucket chan []byte
	bucketSize  int
	saltSize    int
	fromPool    bool
	source      io.Reader
	closed      chan struct{}
}

func NewIodizedSaltGenerator(salt []byte, saltSize, bucketSize int, fromPool bool) (*IodizedSaltGenerator, error) {
	resp, err := http.Get("https://github.com/explore")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error when fetching entropy source: %v %v", resp.StatusCode, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	kdf := hkdf.New(sha1.New, b, salt, []byte("softwind"))
	g := IodizedSaltGenerator{
		tokenBucket: make(chan []byte, bucketSize),
		bucketSize:  bucketSize,
		saltSize:    saltSize,
		source:      kdf,
		closed:      make(chan struct{}),
		fromPool:    fromPool,
	}
	g.start()
	return &g, nil
}

func (g *IodizedSaltGenerator) start() {
	var salt []byte
	for {
		if g.fromPool {
			salt = pool.Get(g.saltSize)
		} else {
			salt = make([]byte, g.saltSize)
		}
		_, err := io.ReadFull(g.source, salt)
		if err != nil {
			break
		}
		select {
		case <-g.closed:
			break
		case g.tokenBucket <- salt:
		}
	}
}

func (g *IodizedSaltGenerator) Get() []byte {
	return <-g.tokenBucket
}

func (g *IodizedSaltGenerator) Close() error {
	close(g.closed)
	return nil
}

type RandomSaltGenerator struct {
	saltSize int
	fromPool bool
}

func NewRandomSaltGenerator(saltSize int, fromPool bool) (*RandomSaltGenerator, error) {
	return &RandomSaltGenerator{
		saltSize: saltSize,
		fromPool: fromPool,
	}, nil
}

func (g *RandomSaltGenerator) Get() []byte {
	var salt []byte
	if g.fromPool {
		salt = pool.Get(g.saltSize)
	} else {
		salt = make([]byte, g.saltSize)
	}
	_, _ = fastrand.Read(salt)
	return salt
}

func (g *RandomSaltGenerator) Close() error {
	return nil
}
