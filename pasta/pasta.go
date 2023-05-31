package pasta

// nada

import (
	"math"
)

const PastaDefaultSecLevel = 128
const SecretKeySize = 256
const PlaintextSize = 128
const CiphertextSize = 128

const NumMatmulsSquares = 3
const LastSquare = false

const Nonce = uint64(123456789)

type Params struct {
	SecretKeySize  uint64
	PlaintextSize  uint64
	CiphertextSize uint64
	Rounds         uint
}

type Pasta struct {
	SecretKey SecretKey
	Modulus   uint64
	Params    Params
}

func NewPasta(secretKey []uint64, modulus uint64, params Params) Pasta {
	pasta := Pasta{
		secretKey,
		modulus,
		params,
	}

	return pasta
}

func (p *Pasta) Encrypt(plaintext []uint64) []uint64 {
	size := len(plaintext)

	numBlock := int(math.Ceil(float64(size) / float64(p.Params.PlaintextSize)))

	pastaUtil := NewUtil(p.SecretKey, p.Modulus, int(p.Params.Rounds))
	ciphertext := make([]uint64, size)
	copy(ciphertext, plaintext)

	for b := uint64(0); b < uint64(numBlock); b++ {
		ks := pastaUtil.Keystream(Nonce, b)
		for i := int(b * p.Params.PlaintextSize); i < int((b+1)*p.Params.PlaintextSize) && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + ks[i-int(b*p.Params.PlaintextSize)]) % p.Modulus
		}
	}

	return ciphertext
}

func (p *Pasta) Decrypt(ciphertext []uint64) []uint64 {
	size := len(ciphertext)

	numBlock := int(math.Ceil(float64(size) / float64(p.Params.CiphertextSize)))

	pasta := NewUtil(p.SecretKey, p.Modulus, int(p.Params.Rounds))
	plaintext := make([]uint64, size)
	copy(plaintext, ciphertext)

	for b := uint64(0); b < uint64(numBlock); b++ {
		ks := pasta.Keystream(Nonce, b)
		for i := int(b * p.Params.CiphertextSize); i < int((b+1)*p.Params.CiphertextSize) && i < size; i++ {
			if ks[i-int(b*p.Params.PlaintextSize)] > plaintext[i] {
				plaintext[i] += p.Modulus
			}
			plaintext[i] = plaintext[i] - ks[i-int(b*p.Params.PlaintextSize)]
		}
	}

	return plaintext
}
