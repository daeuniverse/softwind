package shadowsocks

import (
	"crypto/sha1"
	"fmt"
	"github.com/mzz2017/softwind/ciphers"
	"github.com/mzz2017/softwind/pool"
	"golang.org/x/crypto/hkdf"
	"io"
)

// EncryptUDPFromPool returns shadowBytes from pool.
// the shadowBytes MUST be put back.
func EncryptUDPFromPool(key Key, b []byte, salt []byte) (shadowBytes []byte, err error) {
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
		ciphers.ReusedInfo,
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
func DecryptUDP(key Key, shadowBytes []byte) (n int, err error) {
	if len(shadowBytes) < key.CipherConf.SaltLen {
		return 0, fmt.Errorf("short length to decrypt")
	}
	subKey := pool.Get(key.CipherConf.KeyLen)
	defer pool.Put(subKey)
	kdf := hkdf.New(
		sha1.New,
		key.MasterKey,
		shadowBytes[:key.CipherConf.SaltLen],
		ciphers.ReusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return
	}
	plainText, err := ciph.Open(shadowBytes[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ciphers.ZeroNonce[:key.CipherConf.NonceLen], shadowBytes[key.CipherConf.SaltLen:], nil)
	if err != nil {
		return 0, err
	}
	copy(shadowBytes, plainText)
	return len(plainText), nil
}
