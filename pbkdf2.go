//go:build !cmd_go_bootstrap

package pbkdf2

// #include "/usr/lib/golang/src/vendor/github.com/golang-fips/openssl/v2/goopenssl.h"
import "C"
import (
	"bytes"
	"errors"
	"hash"
	"crypto/sha1"
	"crypto/sha256"
	"unsafe"
)

var (
	emptySha1   = sha1.Sum([]byte{})
	emptySha256 = sha256.Sum256([]byte{})
)

func hashToMD(h hash.Hash) C.GO_EVP_MD_PTR {
	emptyHash := h.Sum([]byte{})

	switch {
	case bytes.Equal(emptyHash, emptySha1[:]):
		return C.go_openssl_EVP_sha1()
	case bytes.Equal(emptyHash, emptySha256[:]):
		return C.go_openssl_EVP_sha256()
	}
	return nil
}

func base(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func sbase(b []byte) *C.char {
	if len(b) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(&b[0]))
}

func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	md := hashToMD(h())
	if md == nil {
		return nil, errors.New("unsupported hash function")
	}
	out := make([]byte, keyLen)
	ok := C.go_openssl_PKCS5_PBKDF2_HMAC(sbase(password), C.int(len(password)), base(salt), C.int(len(salt)), C.int(iter), md, C.int(keyLen), base(out))
	if ok != 1 {
		return nil, errors.New("PKCS5_PBKDF2_HMAC")
	}
	return out, nil
}
