package bfv

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"hhego/pasta"
	"math"
	"testing"
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

func NewBFVPasta(t *testing.T, pastaParams PastaParams, modDegree, plainSize, matrixSize, bsGsN1,
	bsGsN2 uint64, useBsGs bool, plainMod uint64) BFV {

	// set bfv params
	var customParams bfv.ParametersLiteral
	if modDegree == uint64(math.Pow(2, 15)) {
		fmt.Println("polynomial modDegree = 2^15 (32768)")
		//customParams = bfv.PN15QP880
		customParams = bfv.PN15QP827pq
		customParams.T = plainMod
	} else {
		t.Errorf("polynomial modDegree not supported (modDegree)")
	}

	// BFV parameters (128 bit security)
	bfvParams, err := bfv.NewParametersFromLiteral(customParams) // post-quantum params
	if err != nil {
		t.Errorf("couldn't initialize bfvParams")
	}
	keygen := bfv.NewKeyGenerator(bfvParams)
	secretKey, _ := keygen.GenKeyPair()
	bfvEncoder := bfv.NewEncoder(bfvParams)
	evk := EvaluationKeysBfvPasta(matrixSize, plainSize, modDegree, useBsGs, bsGsN2, bsGsN1, *secretKey, bfvParams, keygen)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, evk)

	bfvCipher := NewBFV(bfvParams, secretKey, bfvEvaluator, bfvEncoder, pastaParams, keygen, modDegree, modDegree/2,
		matrixSize, plainSize)

	return bfvCipher
}

func NewBFVBasic(pastaParams PastaParams, modulus uint64) (BFV, Util) {
	// set bfv params
	var params = bfv.PN15QP880
	params.T = modulus

	// BFV parameters (128 bit security)
	bfvParams, _ := bfv.NewParametersFromLiteral(params) // post-quantum params
	keygen := bfv.NewKeyGenerator(bfvParams)
	s, _ := keygen.GenKeyPair()

	// generate evaluation keys
	evk := BasicEvaluationKeys(bfvParams.Parameters, keygen, s)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, evk)
	bfvEncoder := bfv.NewEncoder(bfvParams)
	bfv := NewBFV(bfvParams, s, bfvEvaluator, bfvEncoder, pastaParams, keygen,
		0, 0, 0, 0)

	return bfv, bfv.Util
}

func (b *BFV) Encrypt(plaintext *rlwe.Plaintext) *rlwe.Ciphertext {
	return b.encryptor.EncryptNew(plaintext)
}

func (b *BFV) Transcipher(encryptedMessage []uint64, secretKey *rlwe.Ciphertext) rlwe.Ciphertext {
	pastaUtil := pasta.NewUtil(nil, uint64(b.bfvPastaParams.Modulus), b.bfvPastaParams.PastaRounds)

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

			state = Matmul(state, mat1, mat2, b.slots, b.Halfslots(), b.Evaluator, b.Encoder, b.Params)
			state = AddRc(state, rc, b.Encoder, b.Evaluator, b.Params)
			state = Mix(state, b.Evaluator, b.Encoder)
			if r == b.bfvPastaParams.PastaRounds {
				state = SboxCube(state, b.Evaluator)
			} else {
				state = SboxFeistel(state, b.Halfslots(), b.Evaluator, b.Encoder, b.Params)
			}
		}

		fmt.Println("final add")

		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(b.Halfslots())

		state = Matmul(state, mat1, mat2, b.slots, b.Halfslots(), b.Evaluator, b.Encoder, b.Params)

		state = AddRc(state, rc, b.Encoder, b.Evaluator, b.Params)
		state = Mix(state, b.Evaluator, b.Encoder)

		// add cipher
		start := 0 + (block * b.bfvPastaParams.PastaCiphertextSize)
		end := math.Min(float64((block+1)*b.bfvPastaParams.PastaCiphertextSize), encryptedMessageLength)
		cipherTmp := encryptedMessage[start:int(end)]

		plaintext := b.Encoder.EncodeNew(cipherTmp, state.Level())
		state = b.Evaluator.NegNew(state)
		result[block] = *b.Evaluator.AddNew(state, plaintext) // ct + pt
	}

	return PostProcess(result, b.plainSize, b.matrixSize, b.Evaluator, b.Encoder, b.Params)
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
