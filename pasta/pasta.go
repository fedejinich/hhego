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
	SecretKeySize  uint64
	PlaintextSize  uint64
	CiphertextSize uint64
	Rounds         uint
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

	numBlock := int(math.Ceil(float64(size) / float64(p.CipherParams.PlaintextSize)))

	pastaUtil := NewUtil(p.SecretKey, p.Modulus, int(p.CipherParams.Rounds))
	ciphertext := make([]uint64, size)
	copy(ciphertext, plaintext)

	for b := uint64(0); b < uint64(numBlock); b++ {
		ks := pastaUtil.Keystream(nonce, b)
		for i := int(b * p.CipherParams.PlaintextSize); i < int((b+1)*p.CipherParams.PlaintextSize) && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + ks[i-int(b*p.CipherParams.PlaintextSize)]) % p.Modulus
		}
	}

	return ciphertext
}

func (p *Pasta) Decrypt(ciphertext []uint64) []uint64 {
	nonce := uint64(123456789)
	size := len(ciphertext)

	numBlock := int(math.Ceil(float64(size) / float64(p.CipherParams.CiphertextSize)))

	pasta := NewUtil(p.SecretKey, p.Modulus, int(p.CipherParams.Rounds))
	plaintext := make([]uint64, size)
	copy(plaintext, ciphertext)

	for b := uint64(0); b < uint64(numBlock); b++ {
		ks := pasta.Keystream(nonce, b)
		for i := int(b * p.CipherParams.CiphertextSize); i < int((b+1)*p.CipherParams.CiphertextSize) && i < size; i++ {
			if ks[i-int(b*p.CipherParams.PlaintextSize)] > plaintext[i] {
				plaintext[i] += p.Modulus
			}
			plaintext[i] = plaintext[i] - ks[i-int(b*p.CipherParams.PlaintextSize)]
		}
	}

	return plaintext
}
