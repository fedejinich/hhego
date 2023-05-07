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
	bfvUtil := NewUtil(bfvParams, bfvEncoder, nil, keygen)
	evk := evaluationKeysBfvPasta(matrixSize, plainSize, modDegree, useBsGs, bsGsN2, bsGsN1,
		bfvUtil.Reminder(matrixSize, plainSize), *secretKey, bfvParams, keygen)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, evk)

	bfvCipher := NewBFV(bfvParams, secretKey, bfvEvaluator, bfvEncoder, pastaParams, keygen, modDegree, modDegree/2,
		matrixSize, plainSize)

	return bfvCipher
}

// evaluationKeysBfvPasta creates galois keys (for rotations and relinearization) to transcipher from pasta to bfv
func evaluationKeysBfvPasta(matrixSize uint64, plainSize uint64, modDegree uint64, useBsGs bool,
	bsGsN2 uint64, bsGsN1 uint64, reminder uint64, secretKey rlwe.SecretKey, bfvParams bfv.Parameters, keygen rlwe.KeyGenerator) rlwe.EvaluationKey {

	numBlock := int64(matrixSize / plainSize)
	if reminder > 0 {
		numBlock++
	}
	var flattenGks []int
	for i := int64(1); i < numBlock; i++ {
		flattenGks = append(flattenGks, -int(i*int64(plainSize)))
	}

	var gkIndices []int
	gkIndices = addGkIndices(gkIndices, modDegree, useBsGs)

	// add flatten gks
	for i := 0; i < len(flattenGks); i++ {
		gkIndices = append(gkIndices, flattenGks[i])
	}

	if useBsGs {
		addBsGsIndices(bsGsN1, bsGsN2, &gkIndices, modDegree)
	} else {
		addDiagonalIndices(matrixSize, &gkIndices, modDegree)
	}

	// finally we create the right evaluation set (rotation & reliniarization keys)
	return genEVK(gkIndices, bfvParams.Parameters, keygen, &secretKey)
}

func genEVK(gkIndices []int, params rlwe.Parameters, keygen rlwe.KeyGenerator, secretKey *rlwe.SecretKey) rlwe.EvaluationKey {
	galEls := make([]uint64, len(gkIndices))
	for i, rot := range gkIndices {
		// SEAL uses gkIndex = 0 to represent a column rotation (row in lattigo)
		//    we fix this by generating the right gk for 0 elements
		if rot == 0 {
			galEls[i] = params.GaloisElementForRowRotation()
		} else {
			galEls[i] = params.GaloisElementForColumnRotationBy(rot)
		}
	}

	// set column rotation galois keys
	rks := keygen.GenRotationKeys(galEls, secretKey)
	rlk := keygen.GenRelinearizationKey(secretKey, 1)
	evk := rlwe.EvaluationKey{
		Rlk:  rlk,
		Rtks: rks,
	}

	return evk
}

func addGkIndices(gkIndices []int, degree uint64, useBsGs bool) []int {
	gkIndices = append(gkIndices, 0)
	gkIndices = append(gkIndices, -1)
	if pasta.T*2 != degree {
		gkIndices = append(gkIndices, pasta.T)
	}
	if useBsGs {
		for k := uint64(1); k < BsgsN2; k++ {
			gkIndices = append(gkIndices, int(-k*BsgsN1))
		}
	}
	return gkIndices
}

func addBsGsIndices(n1 uint64, n2 uint64, gkIndices *[]int, slots uint64) {
	mul := n1 * n2
	addDiagonalIndices(mul, gkIndices, slots)

	if n1 == 1 || n2 == 1 {
		return
	}

	for k := uint64(1); k < n2; k++ {
		*gkIndices = append(*gkIndices, int(k*n1))
	}
}

func addDiagonalIndices(matrixSize uint64, gkIndices *[]int, slots uint64) {
	if matrixSize*2 != slots {
		*gkIndices = append(*gkIndices, -int(matrixSize))
	}
	*gkIndices = append(*gkIndices, 1)
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
	evk := basicEvaluationKeys(bfvParams.Parameters, keygen, s)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, evk)
	bfvEncoder := bfv.NewEncoder(bfvParams)
	bfv := NewBFV(bfvParams, s, bfvEvaluator, bfvEncoder, pastaParams, keygen,
		0, 0, 0, 0)

	return bfv, bfv.Util
}

func basicEvaluationKeys(parameters rlwe.Parameters, keygen rlwe.KeyGenerator, key *rlwe.SecretKey) rlwe.EvaluationKey {
	galEl := parameters.GaloisElementForColumnRotationBy(-1)
	galEl2 := parameters.GaloisElementForRowRotation()
	galEl3 := parameters.GaloisElementForColumnRotationBy(pasta.T) // useful for MatMulTest
	els := []uint64{galEl, galEl2, galEl3}

	for k := 0; k < BsgsN2; k++ {
		els = append(els, parameters.GaloisElementForColumnRotationBy(-k*BsgsN1))
	}

	rtks := keygen.GenRotationKeys(els, key)

	return rlwe.EvaluationKey{
		Rlk:  keygen.GenRelinearizationKey(key, 1),
		Rtks: rtks,
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
