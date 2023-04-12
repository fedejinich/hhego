package bfv

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"hhego/pasta"
	"math"
)

// PastaParams todo(fedejinch) refactor this, and reuse the real pastaparams
type PastaParams struct {
	Rounds     int
	CipherSize int
	Modulus    int
}

// SealParams todo(fedejinich) this is temporal, will be removed
type SealParams struct {
	Halfslots uint64 // todo(fedejinich) this should be calcualted
	Slots     uint64
}

type BFVCipher struct {
	encryptor   rlwe.Encryptor
	sealParams  SealParams
	evaluator   bfv.Evaluator
	encoder     bfv.Encoder
	pastaParams PastaParams
	bfvParams   bfv.Parameters
}

func NewBFVCipher(bfvParams bfv.Parameters, key *rlwe.SecretKey, sealParams SealParams, evaluator bfv.Evaluator,
	encoder bfv.Encoder, pastaParams PastaParams) BFVCipher {
	return BFVCipher{
		bfv.NewEncryptor(bfvParams, key),
		sealParams,
		evaluator,
		encoder,
		pastaParams,
		bfvParams,
	}
}

func (bfvCipher *BFVCipher) Encrypt(plaintext *rlwe.Plaintext) *rlwe.Ciphertext {
	return bfvCipher.encryptor.EncryptNew(plaintext)
}

func (bfvCipher *BFVCipher) Decomp(encryptedMessage []uint64, secretKey *rlwe.Ciphertext) []rlwe.Ciphertext {
	nonce := 123456789
	size := len(encryptedMessage)

	numBlock := math.Ceil(float64(size) / float64(bfvCipher.pastaParams.CipherSize)) // todo(fedejinich) float?

	// todo(fedejinich) not sure about secretKey
	pastaUtil := pasta.NewUtil(secretKey.Value[0].Buff, uint64(bfvCipher.pastaParams.Modulus), bfvCipher.pastaParams.Rounds)
	bfvUtil := NewBFVUtil(bfvCipher.bfvParams, bfvCipher.encoder, bfvCipher.evaluator)
	result := make([]rlwe.Ciphertext, int(numBlock))

	for b := 0; b < int(numBlock); b++ {
		pastaUtil.InitShake(uint64(nonce), uint64(b))
		state := secretKey

		// todo(fedejinich) refactor this into (...) = pastaUtil.round(...)
		for r := 1; r < bfvCipher.pastaParams.Rounds; r++ {
			// todo(fedejinich) can be refactored into (mat1, mat2, rc) = pastaUtil.InitParams()
			mat1 := pastaUtil.RandomMatrix()
			mat2 := pastaUtil.RandomMatrix()
			rc := pastaUtil.RCVec(bfvCipher.sealParams.Halfslots)

			bfvUtil.matmulDecomp(state, mat1, mat2, bfvCipher.sealParams)
			bfvUtil.addRcDecomp(state, rc)
			bfvUtil.mixDecomp(state)
			if r == bfvCipher.pastaParams.Rounds {
				bfvUtil.sboxCubeDecomp(state)
			} else {
				bfvUtil.sboxFeistelDecomp(state, bfvCipher.sealParams)
			}

			//printNoise(state)
		}

		// todo(fedejinich) refactor this into (...) = pastaUtil.round(...)
		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(bfvCipher.sealParams.Halfslots)
		bfvUtil.matmulDecomp(state, mat1, mat2, bfvCipher.sealParams)
		bfvUtil.addRcDecomp(state, rc)
		bfvUtil.mixDecomp(state)

		// add cipher
		offset := b * bfvCipher.pastaParams.CipherSize
		size := math.Min(float64((b+1)*bfvCipher.pastaParams.CipherSize), float64(size))
		ciphertextTemp := encryptedMessage[offset:int(size)] // todo(fedejinich) not completely sure about this

		plaintext := bfv.NewPlaintext(bfvCipher.bfvParams, bfvCipher.bfvParams.MaxLevel()) // todo(fedejinich) not sure about MaxLevel()
		bfvCipher.encoder.Encode(ciphertextTemp, plaintext)
		bfvCipher.evaluator.Neg(state, state)            // todo(fedejinich) ugly
		bfvCipher.evaluator.Add(state, plaintext, state) // todo(fedejinich) ugly
		result[b] = *state
	}
	return result
}
