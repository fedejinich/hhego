package bfv

import (
	"fmt"
	"github.com/fedejinich/hhego/pasta"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math"
)

type BFV struct {
	params    bfv.Parameters
	secretKey rlwe.SecretKey
	evk       rlwe.EvaluationKeySet
}

// newBFV default constructor
func newBFV(bfvParams bfv.Parameters, secretKey *rlwe.SecretKey,
	evaluator bfv.Evaluator, encoder bfv.Encoder,
	evk rlwe.EvaluationKeySet) (rlwe.Encryptor, rlwe.Decryptor, bfv.Evaluator,
	bfv.Encoder, BFV) {
	return bfv.NewEncryptor(bfvParams, secretKey),
		bfv.NewDecryptor(bfvParams, secretKey),
		evaluator,
		encoder,
		BFV{
			bfvParams,
			*secretKey,
			evk,
		}
}

func NewBFVPasta(polyDegree, pastaSeclevel, messageLength, bsGsN1, bsGsN2 uint64, useBsGs bool, modulus uint64,
	sk *rlwe.SecretKey, rk *rlwe.RelinearizationKey) (rlwe.Encryptor, rlwe.Decryptor, bfv.Evaluator, bfv.Encoder, BFV) {
	bfvParams := GenerateBfvParams(modulus, polyDegree)
	bfvEncoder := bfv.NewEncoder(bfvParams)
	evk := evaluationKeysBfvPasta(messageLength, pastaSeclevel, polyDegree, useBsGs,
		bsGsN2, bsGsN1, *sk, bfvParams, rk)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, &evk)

	e, d, ev, en, bfvCipher := newBFV(bfvParams, sk, bfvEvaluator, bfvEncoder, evk)

	return e, d, ev, en, bfvCipher
}

// Transcipher translates pasta encrypted messages into bfv encrypted messages
// NOTE: This is a non-deterministic method, two bfv-ciphers with same SK will
// return different ciphertexts. This is because GaloisKeys are generated in
// a non-deterministic way.
// More details about this https://github.com/tuneinsight/lattigo/discussions/397
func (b *BFV) Transcipher(encryptedMessage []uint64, pastaSecretKey *rlwe.Ciphertext, pastaParams pasta.Params,
	pastaSeclevel uint64, encoder bfv.Encoder, evaluator bfv.Evaluator) rlwe.Ciphertext {
	useBsGs := true // enables babystep gigantstep matrix multiplication

	bfvParams := b.params
	pastaUtil := pasta.NewUtil(nil, bfvParams.T(), int(pastaParams.Rounds)) // todo(fedejinich) plainMod == b.bfvParams.T() == pastaParams.Modulus ?

	encryptedMessageLength := uint64(len(encryptedMessage))

	numBlock := int(math.Ceil(float64(encryptedMessageLength) / float64(pastaParams.CiphertextSize)))

	fmt.Printf("Transciphering %d pasta blocks\n", numBlock)

	result := make([]rlwe.Ciphertext, numBlock) // each element represents a pasta decrypted block
	for block := 0; block < numBlock; block++ {
		pastaUtil.InitShake(pasta.Nonce, uint64(block))

		// 'state' contains the two PASTA branches encoded as b.ciphertext
		// s1 := pastaSecretKey[0:halfslots]
		// s2 := pastaSecretKey[:halfslots]
		state := pastaSecretKey

		fmt.Printf("block %d/%d\n", block, numBlock)

		slots := b.slots()
		halfslots := b.halfslots()
		for r := 1; r <= int(pastaParams.Rounds); r++ {
			fmt.Printf("round %d\n", r)

			mat1 := pastaUtil.RandomMatrix()
			mat2 := pastaUtil.RandomMatrix()
			rc := pastaUtil.RCVec(halfslots)

			state = Matmul(state, mat1, mat2, slots, halfslots, evaluator, encoder,
				bfvParams, useBsGs)
			state = AddRc(state, rc, encoder, evaluator, bfvParams)
			state = Mix(state, evaluator, encoder)

			if r == int(pastaParams.Rounds) {
				state = SboxCube(state, evaluator)
			} else {
				state = SboxFeistel(state, halfslots, evaluator, encoder, bfvParams)
			}
		}

		fmt.Println("final add")

		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(halfslots)

		state = Matmul(state, mat1, mat2, slots, halfslots, evaluator, encoder,
			bfvParams, useBsGs)
		state = AddRc(state, rc, encoder, evaluator, bfvParams)
		state = Mix(state, evaluator, encoder)

		// add cipher
		start := 0 + (block * int(pastaParams.CiphertextSize))
		end := math.Min(float64((block+1)*int(pastaParams.CiphertextSize)),
			float64(encryptedMessageLength))
		cipherTmp := encryptedMessage[start:int(end)]

		plaintext := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
		encoder.Encode(cipherTmp, plaintext)
		state = evaluator.NegNew(state)
		result[block] = *evaluator.AddNew(state, plaintext) // ct + pt
	}

	// flatten pasta blocks
	ciphertext := postProcess(result, pastaSeclevel, encryptedMessageLength, evaluator,
		encoder, bfvParams)

	return ciphertext
}

func (b *BFV) DecryptPacked(ciphertext *rlwe.Ciphertext, size uint64,
	decryptor rlwe.Decryptor, encoder bfv.Encoder) []uint64 {
	plaintext := decryptor.DecryptNew(ciphertext)
	dec := encoder.DecodeUintNew(plaintext)

	return dec[:size]
}

func (b *BFV) EncryptPastaSecretKey(secretKey []uint64, encoder bfv.Encoder,
	encryptor rlwe.Encryptor) *rlwe.Ciphertext {
	halfslots := uint64(b.params.N() / 2)
	keyTmp := make([]uint64, halfslots+pasta.T)

	for i := uint64(0); i < pasta.T; i++ {
		secondHalf := i + halfslots

		keyTmp[i] = secretKey[i]
		keyTmp[secondHalf] = secretKey[i+pasta.T]
	}
	plaintext := bfv.NewPlaintext(b.params, b.params.MaxLevel())
	encoder.Encode(keyTmp, plaintext)

	return encryptor.EncryptNew(plaintext)
}

// postProcess creates and applies a masking vector and flattens transciphered pasta blocks into one ciphertext
func postProcess(transcipheredMessage []rlwe.Ciphertext, pastaSeclevel, messageLength uint64, evaluator bfv.Evaluator, encoder bfv.Encoder,
	bfvParams bfv.Parameters) rlwe.Ciphertext {
	rem := messageLength % pastaSeclevel

	if rem != 0 {
		mask := make([]uint64, rem) // create a 1s mask
		for i := range mask {
			mask[i] = 1
		}
		lastIndex := len(transcipheredMessage) - 1
		last := transcipheredMessage[lastIndex].CopyNew()
		plaintext := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
		encoder.Encode(mask, plaintext)

		// mask
		transcipheredMessage[lastIndex] = *evaluator.MulNew(last, plaintext) // ct x pt
	}

	// flatten ciphertexts
	ciphertext := transcipheredMessage[0]
	for i := 1; i < len(transcipheredMessage); i++ {
		tmp := evaluator.RotateColumnsNew(&transcipheredMessage[i], -(i * int(pastaSeclevel)))
		ciphertext = *evaluator.AddNew(&ciphertext, tmp) // ct + ct
	}

	return ciphertext
}

func (b *BFV) slots() uint64 {
	return uint64(b.params.N())
}

func (b *BFV) halfslots() uint64 {
	return b.slots() / 2
}

// evaluationKeysBfvPasta creates evaluation keys (for rotations and relinearization) to transcipher from pasta to bfv
func evaluationKeysBfvPasta(messageLength uint64, pastaSeclevel uint64, modDegree uint64, useBsGs bool, bsGsN2 uint64,
	bsGsN1 uint64, secretKey rlwe.SecretKey, bfvParams bfv.Parameters, rk *rlwe.RelinearizationKey) rlwe.EvaluationKeySet {

	rem := messageLength % pastaSeclevel

	numBlock := int64(messageLength / pastaSeclevel)
	if rem > 0 {
		numBlock++
	}
	var flattenGks []int
	for i := int64(1); i < numBlock; i++ {
		flattenGks = append(flattenGks, -int(i*int64(pastaSeclevel)))
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
		addDiagonalIndices(messageLength, &gkIndices, modDegree)
	}

	// finally we create the right evaluation set (rotation & reliniarization keys)
	evk := buildEvks(gkIndices, bfvParams.Parameters, &secretKey, rk)

	return *evk
}

func buildEvks(gkIndices []int, params rlwe.Parameters, secretKey *rlwe.SecretKey, rk *rlwe.RelinearizationKey) *rlwe.EvaluationKeySet {
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

	evk := GenEvks(params, galEls, secretKey, rk)

	return evk
}
