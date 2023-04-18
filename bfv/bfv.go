package bfv

import (
	"fmt"
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

// SealParams todo(fedejinich) this is temporal, will be removed.
type SealParams struct {
	Halfslots uint64 // todo(fedejinich) this should be calcualted
	Slots     uint64
}

type BFVCipher struct {
	encryptor   rlwe.Encryptor
	decryptor   rlwe.Decryptor
	Evaluator   bfv.Evaluator
	Encoder     bfv.Encoder
	pastaParams *PastaParams
	bfvParams   bfv.Parameters
	Keygen      rlwe.KeyGenerator
	secretKey   rlwe.SecretKey
	slots       uint64 // determined by the polynomial modulus degree of the encryption parameters
	halfslots   uint64 // given by slots // todo(fedejinich) remove this field, it's unnecessary
	gkIndices   []int64
}

func NewBFVCipher(bfvParams bfv.Parameters, key *rlwe.SecretKey, evaluator bfv.Evaluator, encoder bfv.Encoder, pastaParams *PastaParams, keygen rlwe.KeyGenerator, secretKey rlwe.SecretKey, slots, halfslots uint64) BFVCipher {
	return BFVCipher{
		bfv.NewEncryptor(bfvParams, key),
		bfv.NewDecryptor(bfvParams, key),
		evaluator,
		encoder,
		pastaParams,
		bfvParams,
		keygen,
		secretKey,
		slots,
		halfslots,
		[]int64{},
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
	bfvUtil := NewUtil(bfvCipher.bfvParams, bfvCipher.Encoder, bfvCipher.Evaluator, bfvCipher.Keygen,
		bfvCipher.secretKey)
	result := make([]rlwe.Ciphertext, int(numBlock))

	for b := 0; b < int(numBlock); b++ {
		pastaUtil.InitShake(uint64(nonce), uint64(b))
		state := secretKey

		fmt.Printf("block %d\n", b)

		// todo(fedejinich) refactor this into (...) = pastaUtil.round(...)
		for r := 1; r <= bfvCipher.pastaParams.Rounds; r++ {
			fmt.Printf("round %d\n", r)
			// todo(fedejinich) can be refactored into (mat1, mat2, rc) = pastaUtil.InitParams()
			mat1 := pastaUtil.RandomMatrix()
			mat2 := pastaUtil.RandomMatrix()
			rc := pastaUtil.RCVec(bfvCipher.halfslots) // todo(fedejinich) this should have t size as tXt random matrix, right?

			// todo(fedejinich) we can do a huge optimization here: we can do everything it's done in just ONE big matrix,
			//   instead of splitting into two steps
			bfvUtil.Matmul(state, mat1, &state)
			bfvUtil.Matmul(state, mat2, &state)

			bfvUtil.AddRc(state, rc)
			bfvUtil.Mix(state)
			if r == bfvCipher.pastaParams.Rounds {
				bfvUtil.SboxCube(state)
			} else {
				bfvUtil.SboxFeistel(state, bfvCipher.halfslots)
			}

			//printNoise(state)
		}

		fmt.Println("final add")

		// todo(fedejinich) refactor this into (...) = pastaUtil.round(...)
		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(bfvCipher.halfslots)

		// todo(fedejinich) in the c++ impl, everything it's done in just ONE big matrix,
		//   here we split it in two steps (will be refactored)
		bfvUtil.Matmul(state, mat1, &state)
		bfvUtil.Matmul(state, mat2, &state)

		bfvUtil.AddRc(state, rc)
		bfvUtil.Mix(state)

		// add cipher
		offset := b * bfvCipher.pastaParams.CipherSize
		size := math.Min(float64((b+1)*bfvCipher.pastaParams.CipherSize), float64(size))
		ciphertextTemp := encryptedMessage[offset:int(size)] // todo(fedejinich) not completely sure about this

		plaintext := bfv.NewPlaintext(bfvCipher.bfvParams, bfvCipher.bfvParams.MaxLevel()) // todo(fedejinich) not sure about MaxLevel()
		bfvCipher.Encoder.Encode(ciphertextTemp, plaintext)
		bfvCipher.Evaluator.Neg(state, state)            // todo(fedejinich) ugly
		bfvCipher.Evaluator.Add(state, plaintext, state) // todo(fedejinich) ugly
		result[b] = *state
	}
	// todo(fedejinich) shoudl pasta.PlaintextSize be parameterizable?
	return result
}

func (bfvCipher *BFVCipher) Decrypt(ciphertext *rlwe.Ciphertext) *rlwe.Plaintext {
	return bfvCipher.decryptor.DecryptNew(ciphertext)
}

func (bfvCipher *BFVCipher) flatten(decomp []rlwe.Ciphertext, plainSize int) rlwe.Ciphertext {
	// todo(fedejinich) implement this
	ciphertext := decomp[0]
	for i := 1; i < len(decomp); i++ {
		tmp := bfvCipher.Evaluator.RotateColumnsNew(&decomp[i], -(i * plainSize))
		bfvCipher.Evaluator.Add(&ciphertext, tmp, &ciphertext)
	}

	return ciphertext
}

func (bfvCipher *BFVCipher) DecryptPacked(ciphertext *rlwe.Ciphertext, matrixSize uint64) []uint64 {
	plaintext := bfvCipher.decryptor.DecryptNew(ciphertext)
	dec := bfvCipher.Encoder.DecodeUintNew(plaintext)

	return dec[0:matrixSize]
}
