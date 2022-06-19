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

const DefaultBucketSize = 300

var (
	DefaultSaltGeneratorType = IodizedSaltGeneratorType
	DefaultIodizedSource     = "https://github.com/explore"
	saltGenerators           = make(map[int]SaltGenerator)
	muGenerators             sync.Mutex
)

func GetSaltGenerator(masterKey []byte, saltLen int) (sg SaltGenerator, err error) {
	muGenerators.Lock()
	sg, ok := saltGenerators[saltLen]
	if !ok {
		dummy := NewDummySaltGenerator()
		saltGenerators[saltLen] = dummy
		muGenerators.Unlock()
		defer func() {
			dummy.Success = err == nil
			close(dummy.Closed)
		}()
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
		muGenerators.Lock()
		saltGenerators[saltLen] = sg
		muGenerators.Unlock()
	} else {
		muGenerators.Unlock()
		if g, isBuilding := sg.(*DummySaltGenerator); isBuilding {
			<-g.Closed
			if g.Success {
				muGenerators.Lock()
				sg = saltGenerators[saltLen]
				muGenerators.Unlock()
			} else {
				return GetSaltGenerator(masterKey, saltLen)
			}
		}
	}
	return sg, nil
}

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
	resp, err := http.Get(DefaultIodizedSource)
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

type DummySaltGenerator struct {
	Closed  chan struct{}
	Success bool
}

func NewDummySaltGenerator() *DummySaltGenerator {
	return &DummySaltGenerator{Closed: make(chan struct{})}
}

func (g *DummySaltGenerator) Get() []byte {
	return nil
}

func (g *DummySaltGenerator) Close() error {
	close(g.Closed)
	return nil
}
