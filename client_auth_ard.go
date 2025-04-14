package vnc

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
)

// Apple VNC Server Authentication
type ARDAuth struct {
	Username string
	Password string
}

func (p *ARDAuth) SecurityType() uint8 {
	return 30
}

func (p *ARDAuth) Handshake(c net.Conn) error {
	// Adapted from https://github.com/novnc/noVNC/commit/e21ed2e6898f28f6fb4dc0e94dd3d8e08e99efb0

	var keyLength uint16
	generator := make([]byte, 2)
	if _, err := io.ReadFull(c, generator); err != nil {
		return err
	}
	if err := binary.Read(c, binary.BigEndian, &keyLength); err != nil {
		return err
	}

	prime := make([]byte, keyLength)
	serverPublicKey := make([]byte, keyLength)
	if _, err := io.ReadFull(c, prime); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, serverPublicKey); err != nil {
		return err
	}

	clientPrivateKey := make([]byte, keyLength)
	if _, err := rand.Read(clientPrivateKey); err != nil {
		return err
	}

	padding := make([]byte, 64)
	if _, err := rand.Read(padding); err != nil {
		return err
	}

	// calculate the DH keys
	clientPublicKey := modPow(generator, clientPrivateKey, prime)
	sharedKey := modPow(serverPublicKey, clientPrivateKey, prime)

	paddedUsername := append(append([]byte(p.Username), '\x00'), padding...)
	paddedPassword := append(append([]byte(p.Password), '\x00'), padding...)
	credentials := append(paddedUsername[0:64], paddedPassword[0:64]...)

	ardCredentials, err := aesEcbEncrypt(sharedKey, credentials)
	if err != nil {
		return err
	}

	if _, err := c.Write(ardCredentials); err != nil {
		return err
	}
	if _, err := c.Write(clientPublicKey); err != nil {
		return err
	}
	return nil
}

func aesEcbEncrypt(key, data []byte) ([]byte, error) {
	aesKey := md5.Sum(key)

	b, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}

	bs := b.BlockSize()
	enc := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		b.Encrypt(enc[i:i+bs], data[i:i+bs])
	}
	return enc, nil
}

func modPow(baseB, exponentB, modulusB []byte) []byte {
	base := new(big.Int).SetBytes(baseB)
	exponent := new(big.Int).SetBytes(exponentB)
	modulus := new(big.Int).SetBytes(modulusB)

	result := new(big.Int).Exp(base, exponent, modulus)

	bs := make([]byte, len(modulusB))
	return result.FillBytes(bs)
}
