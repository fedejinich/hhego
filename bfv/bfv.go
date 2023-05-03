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

type BFVCipher struct {
	encryptor rlwe.Encryptor
	decryptor rlwe.Decryptor
	Evaluator bfv.Evaluator
	Encoder   bfv.Encoder
	Keygen    rlwe.KeyGenerator
	bfvParams bfv.Parameters
	secretKey rlwe.SecretKey

	pastaParams *PastaParams
	slots       uint64 // determined by the polynomial modulus degree of the encryption parameters
	halfslots   uint64 // given by slots // todo(fedejinich) remove this field, it's unnecessary
}

var CustomBFVParams = bfv.ParametersLiteral{
	LogN: 15, // 2^15 = 32768
	Q: []uint64{0x7fffffffe90001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001, 0x7fffffffaa0001,
		0x7fffffffa50001, 0x7fffffff9f0001, 0x7fffffff7e0001, 0x7fffffff770001, 0x7fffffff380001,
		0x7fffffff330001, 0x7fffffff2d0001, 0x7fffffff170001, 0x7fffffff150001, 0x7ffffffef00001,
		0xfffffffff70001}, // same SEAL coeff_modulus (Total bit count: 881 = 15 * 55 + 56)
	//P: []uint64{}, // todo(fedejinich) SEAL uses this as expand_mod_chain
	T: 65537,
}

func NewBFVCipher(bfvParams bfv.Parameters, secretKey *rlwe.SecretKey, evaluator bfv.Evaluator, encoder bfv.Encoder,
	pastaParams *PastaParams, keygen rlwe.KeyGenerator, slots, halfslots uint64) BFVCipher {
	return BFVCipher{
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

func (bfvCipher *BFVCipher) Encrypt(plaintext *rlwe.Plaintext) *rlwe.Ciphertext {
	return bfvCipher.encryptor.EncryptNew(plaintext)
}

func (bfvCipher *BFVCipher) Decomp(encryptedMessage []uint64, secretKey *rlwe.Ciphertext) []rlwe.Ciphertext {
	nonce := 123456789
	size := len(encryptedMessage)

	// calculates the amount of PASTA blocks needed
	numBlock := math.Ceil(float64(size) / float64(bfvCipher.pastaParams.CipherSize)) // todo(fedejinich) float?

	pastaUtil := pasta.NewUtil(nil, uint64(bfvCipher.pastaParams.Modulus), bfvCipher.pastaParams.Rounds)
	bfvUtil := NewUtil(bfvCipher.bfvParams, bfvCipher.Encoder, bfvCipher.Evaluator, bfvCipher.Keygen,
		bfvCipher.secretKey)

	result := make([]rlwe.Ciphertext, int(numBlock))
	for b := 0; b < int(numBlock); b++ {
		pastaUtil.InitShake(uint64(nonce), uint64(b))
		// 'state' contains the two PASTA branches encoded as bfv.ciphertext
		// s1 := secretKey[0:halfslots]
		// s1 := secretKey[:halfslots]
		state := secretKey

		fmt.Printf("block %d\n", b)

		for r := 1; r <= bfvCipher.pastaParams.Rounds; r++ {
			fmt.Printf("round %d\n", r)
			mat1 := pastaUtil.RandomMatrix()
			//mat1 := fixedMatrix1()
			//mat2 := fixedMatrix2()
			mat2 := pastaUtil.RandomMatrix()
			rc := pastaUtil.RCVec(bfvCipher.halfslots)

			state = bfvUtil.Matmul(state, mat1, mat2, bfvCipher.slots, bfvCipher.halfslots)
			state = bfvUtil.AddRc(state, rc)
			state = bfvUtil.Mix(state)
			if r == bfvCipher.pastaParams.Rounds {
				state = bfvUtil.SboxCube(state)
			} else {
				state = bfvUtil.SboxFeistel(state, bfvCipher.halfslots)
			}
		}

		fmt.Println("final add")

		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(bfvCipher.halfslots)

		state = bfvUtil.Matmul(state, mat1, mat2, bfvCipher.slots, bfvCipher.halfslots)

		state = bfvUtil.AddRc(state, rc)
		state = bfvUtil.Mix(state)

		// add cipher
		//offset := b * bfvCipher.pastaParams.CipherSize
		//ciphertextTemp := encryptedMessage[offset:int(size)] // todo(fedejinich) not completely sure about this
		//cipherTmp = append(cipherTmp,
		//	encryptedMessage[b*bfvCipher.pastaParams.CipherSize:min(int64((b+1)*bfvCipher.pastaParams.CipherSize), int64(size))]...)
		start := 0 + (b * bfvCipher.pastaParams.CipherSize)
		end := math.Min(float64((b+1)*bfvCipher.pastaParams.CipherSize), float64(size))
		cipherTmp := encryptedMessage[start:int(end)]

		plaintext := bfvCipher.Encoder.EncodeNew(cipherTmp, state.Level())
		state = bfvCipher.Evaluator.NegNew(state)
		result[b] = *bfvCipher.Evaluator.AddNew(state, plaintext)
	}
	return result
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (bfvCipher *BFVCipher) Decrypt(ciphertext *rlwe.Ciphertext) *rlwe.Plaintext {
	return bfvCipher.decryptor.DecryptNew(ciphertext)
}

func (bfvCipher *BFVCipher) DecryptPacked(ciphertext *rlwe.Ciphertext, matrixSize uint64) []uint64 {
	plaintext := bfvCipher.decryptor.DecryptNew(ciphertext)
	dec := bfvCipher.Encoder.DecodeUintNew(plaintext)

	return dec[0:matrixSize]
}

func (bfvCipher *BFVCipher) EncryptPastaSecretKey(secretKey []uint64) *rlwe.Ciphertext {
	keyTmp := make([]uint64, bfvCipher.Halfslots()+pasta.T)

	for i := uint64(0); i < pasta.T; i++ {
		keyTmp[i] = secretKey[i]
		keyTmp[i+bfvCipher.Halfslots()] = secretKey[i+pasta.T]
	}
	plaintext := bfvCipher.Encoder.EncodeNew(keyTmp, bfvCipher.bfvParams.MaxLevel())

	return bfvCipher.Encrypt(plaintext)
}

func (bfvCipher *BFVCipher) Halfslots() uint64 {
	return bfvCipher.halfslots // todo(fedejinich) it should be calcualted, refactor this ugly thing
}
