package pasta

import (
	"math"
)

const SecretKeySize = 256
const PlaintextSize = 128
const CiphertextSize = 128

const NumMatmulsSquares = 3
const LastSquare = false

// todo(fedejinich) refactor this to PastaParams
type Params struct {
	SecretKeySize uint64
	PlainSize     uint64
	CipherSize    uint64
	Rounds        uint
}

type Pasta struct {
	SecretKey    SecretKey
	Modulus      uint64
	CipherParams Params
}

func NewPasta(secretKey []uint64, modulus uint64, cipherParams Params) Pasta {
	pasta := Pasta{
		secretKey,
		modulus,
		cipherParams,
	}

	return pasta
}

func (p *Pasta) Encrypt(plaintext []uint64) []uint64 {
	nonce := uint64(123456789)
	size := len(plaintext)

	numBlock := int(math.Ceil(float64(size) / float64(p.CipherParams.PlainSize)))

	pastaUtil := NewUtil(p.SecretKey, p.Modulus, int(p.CipherParams.Rounds))
	ciphertext := make([]uint64, size)
	copy(ciphertext, plaintext)

	for b := uint64(0); b < uint64(numBlock); b++ {
		ks := pastaUtil.Keystream(nonce, b)
		for i := int(b * p.CipherParams.PlainSize); i < int((b+1)*p.CipherParams.PlainSize) && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + ks[i-int(b*p.CipherParams.PlainSize)]) % p.Modulus
		}
	}

	return ciphertext
}

func (p *Pasta) Decrypt(ciphertext []uint64) []uint64 {
	nonce := uint64(123456789)
	size := len(ciphertext)

	numBlock := int(math.Ceil(float64(size) / float64(p.CipherParams.CipherSize)))

	pasta := NewUtil(p.SecretKey, p.Modulus, int(p.CipherParams.Rounds))
	plaintext := make([]uint64, size)
	copy(plaintext, ciphertext)

	for b := uint64(0); b < uint64(numBlock); b++ {
		ks := pasta.Keystream(nonce, b)
		for i := int(b * p.CipherParams.CipherSize); i < int((b+1)*p.CipherParams.CipherSize) && i < size; i++ {
			if ks[i-int(b*p.CipherParams.PlainSize)] > plaintext[i] {
				plaintext[i] += p.Modulus
			}
			plaintext[i] = plaintext[i] - ks[i-int(b*p.CipherParams.PlainSize)]
		}
	}

	return plaintext
}
