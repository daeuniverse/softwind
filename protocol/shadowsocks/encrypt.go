package shadowsocks

import (
	"crypto/sha1"
	"fmt"
	"io"

	"github.com/daeuniverse/softwind/ciphers"
	"github.com/daeuniverse/softwind/pool"
	"golang.org/x/crypto/hkdf"
)

// EncryptUDPFromPool returns shadowBytes from pool.
// the shadowBytes MUST be put back.
func EncryptUDPFromPool(key *Key, b []byte, salt []byte, reusedInfo []byte) (shadowBytes pool.PB, err error) {
	var buf = pool.Get(key.CipherConf.SaltLen + len(b) + key.CipherConf.TagLen)
	defer func() {
		if err != nil {
			pool.Put(buf)
		}
	}()
	copy(buf, salt)
	subKey := pool.Get(key.CipherConf.KeyLen)
	defer pool.Put(subKey)
	kdf := hkdf.New(
		sha1.New,
		key.MasterKey,
		buf[:key.CipherConf.SaltLen],
		reusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return nil, err
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return nil, err
	}
	_ = ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ciphers.ZeroNonce[:key.CipherConf.NonceLen], b, nil)
	return buf, nil
}

// DecryptUDP will decrypt the data in place
func DecryptUDPFromPool(key *Key, shadowBytes []byte, reusedInfo []byte) (buf pool.PB, err error) {
	if len(shadowBytes) < key.CipherConf.SaltLen {
		return nil, fmt.Errorf("short length to decrypt")
	}
	subKey := pool.Get(key.CipherConf.KeyLen)
	defer pool.Put(subKey)
	kdf := hkdf.New(
		sha1.New,
		key.MasterKey,
		shadowBytes[:key.CipherConf.SaltLen],
		reusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return
	}
	buf = pool.Get(len(shadowBytes))
	buf, err = ciph.Open(buf[:0], ciphers.ZeroNonce[:key.CipherConf.NonceLen], shadowBytes[key.CipherConf.SaltLen:], nil)
	if err != nil {
		buf.Put()
		return nil, err
	}
	return buf, nil
}
