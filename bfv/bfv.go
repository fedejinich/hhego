package bfv

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"hhego/pasta"
	"math"
)

type BFV struct {
	encryptor rlwe.Encryptor
	decryptor rlwe.Decryptor
	Evaluator bfv.Evaluator
	Encoder   bfv.Encoder
	Keygen    rlwe.KeyGenerator
	Params    bfv.Parameters
	secretKey rlwe.SecretKey
	Util      Util

	// parameters used for PASTA transciphering
	matrixSize     uint64 // size of the pasta-bfv decryption matrix
	plainSize      uint64 // pasta plaintext size
	bfvPastaParams PastaParams
	slots          uint64 // determined by the polynomial modulus degree of the encryption parameters
	halfslots      uint64 // given by slots // todo(fedejinich) remove this field, it's unnecessary
}

type PastaParams struct {
	PastaRounds         int
	PastaCiphertextSize int
	Modulus             int
}

func NewBFV(bfvParams bfv.Parameters, secretKey *rlwe.SecretKey, evaluator bfv.Evaluator, encoder bfv.Encoder,
	bfvPastaParams PastaParams, keygen rlwe.KeyGenerator, slots, halfslots, matrixSize, plainSize uint64) BFV {
	return BFV{
		bfv.NewEncryptor(bfvParams, secretKey),
		bfv.NewDecryptor(bfvParams, secretKey),
		evaluator,
		encoder,
		keygen,
		bfvParams,
		*secretKey,
		NewUtil(bfvParams, encoder, evaluator, keygen),
		matrixSize,
		plainSize,
		bfvPastaParams,
		slots,
		halfslots,
	}
}

func (b *BFV) Encrypt(plaintext *rlwe.Plaintext) *rlwe.Ciphertext {
	return b.encryptor.EncryptNew(plaintext)
}

func (b *BFV) Transcipher(encryptedMessage []uint64, secretKey *rlwe.Ciphertext) rlwe.Ciphertext {
	pastaUtil := pasta.NewUtil(nil, uint64(b.bfvPastaParams.Modulus), b.bfvPastaParams.PastaRounds)
	bfvUtil := NewUtil(b.Params, b.Encoder, b.Evaluator, b.Keygen)

	encryptedMessageLength := float64(len(encryptedMessage))

	numBlock := pastaUtil.BlockCount(encryptedMessageLength, float64(b.bfvPastaParams.PastaCiphertextSize))

	result := make([]rlwe.Ciphertext, numBlock) // each element represents a pasta decrypted block
	for block := 0; block < numBlock; block++ {
		pastaUtil.InitShake(pasta.Nonce, uint64(block))

		// 'state' contains the two PASTA branches encoded as b.ciphertext
		// s1 := secretKey[0:halfslots]
		// s1 := secretKey[:halfslots]
		state := secretKey

		fmt.Printf("block %d\n", block)

		for r := 1; r <= b.bfvPastaParams.PastaRounds; r++ {
			fmt.Printf("round %d\n", r)
			mat1 := pastaUtil.RandomMatrix()
			mat2 := pastaUtil.RandomMatrix()
			rc := pastaUtil.RCVec(b.Halfslots())

			state = bfvUtil.Matmul(state, mat1, mat2, b.slots, b.Halfslots())
			state = bfvUtil.AddRc(state, rc)
			state = bfvUtil.Mix(state)
			if r == b.bfvPastaParams.PastaRounds {
				state = bfvUtil.SboxCube(state)
			} else {
				state = bfvUtil.SboxFeistel(state, b.Halfslots())
			}
		}

		fmt.Println("final add")

		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(b.Halfslots())

		state = bfvUtil.Matmul(state, mat1, mat2, b.slots, b.Halfslots())

		state = bfvUtil.AddRc(state, rc)
		state = bfvUtil.Mix(state)

		// add cipher
		start := 0 + (block * b.bfvPastaParams.PastaCiphertextSize)
		end := math.Min(float64((block+1)*b.bfvPastaParams.PastaCiphertextSize), encryptedMessageLength)
		cipherTmp := encryptedMessage[start:int(end)]

		plaintext := b.Encoder.EncodeNew(cipherTmp, state.Level())
		state = b.Evaluator.NegNew(state)
		result[block] = *b.Evaluator.AddNew(state, plaintext) // ct + pt
	}

	return b.postProcess(result)
}

// postProcess creates and applies a masking vector and flattens transciphered pasta blocks into one ciphertext
func (b *BFV) postProcess(decomp []rlwe.Ciphertext) rlwe.Ciphertext {
	reminder := b.Util.Reminder(b.matrixSize, b.plainSize)

	if reminder != 0 {
		mask := make([]uint64, reminder) // create a 1s mask
		for i := range mask {
			mask[i] = 1
		}
		lastIndex := len(decomp) - 1
		last := decomp[lastIndex]
		plaintext := bfv.NewPlaintext(b.Params, last.Level()) // halfslots
		b.Encoder.Encode(mask, plaintext)
		// mask
		decomp[lastIndex] = *b.Evaluator.MulNew(&last, plaintext) // ct x pt
	}

	// flatten ciphertexts
	ciphertext := decomp[0]
	for i := 1; i < len(decomp); i++ {
		tmp := b.Evaluator.RotateColumnsNew(&decomp[i], -(i * int(b.plainSize)))
		ciphertext = *b.Evaluator.AddNew(&ciphertext, tmp) // ct + ct
	}

	return ciphertext
}

func (b *BFV) Decrypt(ciphertext *rlwe.Ciphertext) *rlwe.Plaintext {
	return b.decryptor.DecryptNew(ciphertext)
}

func (b *BFV) DecryptPacked(ciphertext *rlwe.Ciphertext, matrixSize uint64) []uint64 {
	plaintext := b.decryptor.DecryptNew(ciphertext)
	dec := b.Encoder.DecodeUintNew(plaintext)

	return dec[0:matrixSize]
}

func (b *BFV) EncryptPastaSecretKey(secretKey []uint64) *rlwe.Ciphertext {
	keyTmp := make([]uint64, b.Halfslots()+pasta.T)

	for i := uint64(0); i < pasta.T; i++ {
		keyTmp[i] = secretKey[i]
		keyTmp[i+b.Halfslots()] = secretKey[i+pasta.T]
	}
	plaintext := b.Encoder.EncodeNew(keyTmp, b.Params.MaxLevel())

	return b.Encrypt(plaintext)
}

func (b *BFV) Halfslots() uint64 {
	return b.slots / 2
}
