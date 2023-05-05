package bfv

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"hhego/pasta"
	"math"
)

// BfvPastaParams todo(fedejinch) refactor this, and reuse the real pastaparams
type BfvPastaParams struct {
	PastaRounds         int
	PastaCiphertextSize int
	Modulus             int
}

type BFV struct {
	encryptor rlwe.Encryptor
	decryptor rlwe.Decryptor
	Evaluator bfv.Evaluator
	Encoder   bfv.Encoder
	Keygen    rlwe.KeyGenerator
	Params    bfv.Parameters
	secretKey rlwe.SecretKey

	bfvPastaParams *BfvPastaParams
	slots          uint64 // determined by the polynomial modulus degree of the encryption parameters
	halfslots      uint64 // given by slots // todo(fedejinich) remove this field, it's unnecessary
}

func NewBFV(bfvParams bfv.Parameters, secretKey *rlwe.SecretKey, evaluator bfv.Evaluator, encoder bfv.Encoder,
	pastaParams *BfvPastaParams, keygen rlwe.KeyGenerator, slots, halfslots uint64) BFV {
	return BFV{
		bfv.NewEncryptor(bfvParams, secretKey),
		bfv.NewDecryptor(bfvParams, secretKey),
		evaluator,
		encoder,
		keygen,
		bfvParams,
		*secretKey,
		pastaParams,
		slots,
		halfslots,
	}
}

func (bfv *BFV) Encrypt(plaintext *rlwe.Plaintext) *rlwe.Ciphertext {
	return bfv.encryptor.EncryptNew(plaintext)
}

func (bfv *BFV) Decomp(encryptedMessage []uint64, secretKey *rlwe.Ciphertext) []rlwe.Ciphertext {
	nonce := 123456789
	size := len(encryptedMessage)

	// calculates the amount of PASTA blocks needed
	numBlock := math.Ceil(float64(size) / float64(bfv.bfvPastaParams.PastaCiphertextSize)) // todo(fedejinich) float?

	pastaUtil := pasta.NewUtil(nil, uint64(bfv.bfvPastaParams.Modulus), bfv.bfvPastaParams.PastaRounds)
	bfvUtil := NewUtil(bfv.Params, bfv.Encoder, bfv.Evaluator, bfv.Keygen,
		bfv.secretKey)

	result := make([]rlwe.Ciphertext, int(numBlock))
	for b := 0; b < int(numBlock); b++ {
		pastaUtil.InitShake(uint64(nonce), uint64(b))
		// 'state' contains the two PASTA branches encoded as bfv.ciphertext
		// s1 := secretKey[0:halfslots]
		// s1 := secretKey[:halfslots]
		state := secretKey

		fmt.Printf("block %d\n", b)

		for r := 1; r <= bfv.bfvPastaParams.PastaRounds; r++ {
			fmt.Printf("round %d\n", r)
			mat1 := pastaUtil.RandomMatrix()
			//mat1 := fixedMatrix1()
			//mat2 := fixedMatrix2()
			mat2 := pastaUtil.RandomMatrix()
			rc := pastaUtil.RCVec(bfv.halfslots)

			state = bfvUtil.Matmul(state, mat1, mat2, bfv.slots, bfv.halfslots)
			state = bfvUtil.AddRc(state, rc)
			state = bfvUtil.Mix(state)
			if r == bfv.bfvPastaParams.PastaRounds {
				state = bfvUtil.SboxCube(state)
			} else {
				state = bfvUtil.SboxFeistel(state, bfv.halfslots)
			}
		}

		fmt.Println("final add")

		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(bfv.halfslots)

		state = bfvUtil.Matmul(state, mat1, mat2, bfv.slots, bfv.halfslots)

		state = bfvUtil.AddRc(state, rc)
		state = bfvUtil.Mix(state)

		// add cipher
		//offset := b * bfv.bfvPastaParams.CiphertextSize
		//ciphertextTemp := encryptedMessage[offset:int(size)] // todo(fedejinich) not completely sure about this
		//cipherTmp = append(cipherTmp,
		//	encryptedMessage[b*bfv.bfvPastaParams.CiphertextSize:min(int64((b+1)*bfv.bfvPastaParams.CiphertextSize), int64(size))]...)
		start := 0 + (b * bfv.bfvPastaParams.PastaCiphertextSize)
		end := math.Min(float64((b+1)*bfv.bfvPastaParams.PastaCiphertextSize), float64(size))
		cipherTmp := encryptedMessage[start:int(end)]

		plaintext := bfv.Encoder.EncodeNew(cipherTmp, state.Level())
		state = bfv.Evaluator.NegNew(state)
		result[b] = *bfv.Evaluator.AddNew(state, plaintext)
	}
	return result
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (bfv *BFV) Decrypt(ciphertext *rlwe.Ciphertext) *rlwe.Plaintext {
	return bfv.decryptor.DecryptNew(ciphertext)
}

func (bfv *BFV) DecryptPacked(ciphertext *rlwe.Ciphertext, matrixSize uint64) []uint64 {
	plaintext := bfv.decryptor.DecryptNew(ciphertext)
	dec := bfv.Encoder.DecodeUintNew(plaintext)

	return dec[0:matrixSize]
}

func (bfv *BFV) EncryptPastaSecretKey(secretKey []uint64) *rlwe.Ciphertext {
	keyTmp := make([]uint64, bfv.Halfslots()+pasta.T)

	for i := uint64(0); i < pasta.T; i++ {
		keyTmp[i] = secretKey[i]
		keyTmp[i+bfv.Halfslots()] = secretKey[i+pasta.T]
	}
	plaintext := bfv.Encoder.EncodeNew(keyTmp, bfv.Params.MaxLevel())

	return bfv.Encrypt(plaintext)
}

func (bfv *BFV) Halfslots() uint64 {
	return bfv.halfslots // todo(fedejinich) it should be calcualted, refactor this ugly thing
}
