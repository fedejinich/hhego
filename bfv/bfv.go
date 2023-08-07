package bfv

import (
	"fmt"
	"github.com/fedejinich/hhego/pasta"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math"
)

type BFV struct {
	encryptor rlwe.Encryptor // todo(fedejinich) this is unnecesary`
	decryptor rlwe.Decryptor // todo(fedejinich) this is unnecesary
	Evaluator bfv.Evaluator  // todo(fedejinich) this is unnecesary
	Encoder   bfv.Encoder    // todo(fedejinich) this is unnecesary
	Params    bfv.Parameters
	SecretKey rlwe.SecretKey // todo(fedejinich) this should be private
	Util      BFVUtil
	Evk       rlwe.EvaluationKeySet
	GalEls    []uint64
}

//type PastaParams struct {
//	PastaRounds         int
//	PastaCiphertextSize int
//	Modulus             int
//}

// newBFV default constructor
func newBFV(bfvParams bfv.Parameters, secretKey *rlwe.SecretKey, evaluator bfv.Evaluator, encoder bfv.Encoder, evk rlwe.EvaluationKeySet, galEls []uint64) BFV {
	return BFV{
		bfv.NewEncryptor(bfvParams, secretKey),
		bfv.NewDecryptor(bfvParams, secretKey),
		evaluator,
		encoder,
		bfvParams,
		*secretKey,
		NewBFVUtil(bfvParams, encoder, evaluator),
		evk,
		galEls,
	}
}

func NewBFV(modulus, polyDegree uint64) BFV {
	bfvParams := generateBfvParams(modulus, polyDegree)
	keygen := bfv.NewKeyGenerator(bfvParams)
	s, _ := keygen.GenKeyPairNew()
	evk := BasicEvaluationKeys(bfvParams.Parameters, *keygen, s)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, &evk)
	bfvEncoder := bfv.NewEncoder(bfvParams)

	cipher := newBFV(bfvParams, s, bfvEvaluator, bfvEncoder, evk, []uint64{}) // todo(fedejinich) this is ugly

	return cipher
}

func NewBFVPastaCipher(modDegree, pastaSeclevel, messageLength, bsGsN1, bsGsN2 uint64, useBsGs bool, plainMod uint64) BFV {
	bfvParams := generateBfvParams(plainMod, modDegree)
	keygen := bfv.NewKeyGenerator(bfvParams)
	secretKey, _ := keygen.GenKeyPairNew()
	bfvEncoder := bfv.NewEncoder(bfvParams)
	evk := EvaluationKeysBfvPasta(messageLength, pastaSeclevel, modDegree, useBsGs,
		bsGsN2, bsGsN1, *secretKey, bfvParams, *keygen)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, &evk)

	bfvCipher := newBFV(bfvParams, secretKey, bfvEvaluator, bfvEncoder, evk, []uint64{}) // todo(fedejinich) this is ugly

	return bfvCipher
}

func NewCipherPastaWithSKAndRK(modDegree, pastaSeclevel, messageLength, bsGsN1, bsGsN2 uint64, useBsGs bool,
	plainMod uint64, sk *rlwe.SecretKey, rk *rlwe.RelinearizationKey) BFV {

	bfvParams := generateBfvParams(plainMod, modDegree)
	bfvEncoder := bfv.NewEncoder(bfvParams)
	evk, galEls := EvaluationKeysBfvPasta2(messageLength, pastaSeclevel, modDegree, useBsGs, bsGsN2, bsGsN1, *sk, bfvParams, rk)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, &evk)

	bfvCipher := newBFV(bfvParams, sk, bfvEvaluator, bfvEncoder, evk, galEls)

	fmt.Println(fmt.Sprintf("NewCipherPasta(modDegree%d,pastaSecLevel%d,messageLen%d,plainMod%d\n",
		modDegree, pastaSeclevel, messageLength, plainMod))

	return bfvCipher
}

func (b *BFV) WithEvks(evks rlwe.EvaluationKeySet) {
	b.Evk = evks
	b.Evaluator = b.Evaluator.WithKey(&b.Evk)
}

func (b *BFV) Encrypt(plaintext *rlwe.Plaintext) *rlwe.Ciphertext {
	return b.encryptor.EncryptNew(plaintext)
}

// Transcipher translates pasta encrypted messages into bfv encrypted messages
// NOTE: This is a non-deterministic method, two bfv-ciphers with same SK will
// return different ciphertexts. This is because GaloisKeys are generated in
// a non-deterministic way.
// More details about this https://github.com/tuneinsight/lattigo/discussions/397
func (b *BFV) Transcipher(encryptedMessage []uint64, pastaSecretKey *rlwe.Ciphertext, pastaParams pasta.Params, pastaSeclevel uint64) rlwe.Ciphertext {
	useBsGs := true // enables babystep gigantstep matrix multiplication

	pastaUtil := pasta.NewUtil(nil, b.Params.T(), int(pastaParams.Rounds)) // todo(fedejinich) plainMod == b.Params.T() == pastaParams.Modulus ?

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

		for r := 1; r <= int(pastaParams.Rounds); r++ {
			fmt.Printf("round %d\n", r)

			mat1 := pastaUtil.RandomMatrix()
			mat2 := pastaUtil.RandomMatrix()
			rc := pastaUtil.RCVec(b.Halfslots())

			state = Matmul(state, mat1, mat2, b.Slots(), b.Halfslots(), b.Evaluator, b.Encoder, b.Params, useBsGs)
			state = AddRc(state, rc, b.Encoder, b.Evaluator, b.Params)
			state = Mix(state, b.Evaluator, b.Encoder)

			if r == int(pastaParams.Rounds) {
				state = SboxCube(state, b.Evaluator)
			} else {
				state = SboxFeistel(state, b.Halfslots(), b.Evaluator, b.Encoder, b.Params)
			}
		}

		fmt.Println("final add")

		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(b.Halfslots())

		state = Matmul(state, mat1, mat2, b.Slots(), b.Halfslots(), b.Evaluator, b.Encoder, b.Params, useBsGs)
		state = AddRc(state, rc, b.Encoder, b.Evaluator, b.Params)
		state = Mix(state, b.Evaluator, b.Encoder)

		// add cipher
		start := 0 + (block * int(pastaParams.CiphertextSize))
		end := math.Min(float64((block+1)*int(pastaParams.CiphertextSize)), float64(encryptedMessageLength))
		cipherTmp := encryptedMessage[start:int(end)]

		plaintext := bfv.NewPlaintext(b.Params, b.Params.MaxLevel())
		b.Encoder.Encode(cipherTmp, plaintext)
		state = b.Evaluator.NegNew(state)
		result[block] = *b.Evaluator.AddNew(state, plaintext) // ct + pt
	}

	return PostProcess(result, pastaSeclevel, encryptedMessageLength, b.Evaluator, b.Encoder, b.Params)
}

func (b *BFV) Decrypt(ciphertext *rlwe.Ciphertext) *rlwe.Plaintext {
	return b.decryptor.DecryptNew(ciphertext)
}

func (b *BFV) DecryptPacked(ciphertext *rlwe.Ciphertext, size uint64) []uint64 {
	plaintext := b.decryptor.DecryptNew(ciphertext)
	dec := b.Encoder.DecodeUintNew(plaintext)

	return dec[:size]
}

func (b *BFV) EncryptPastaSecretKey(secretKey []uint64) *rlwe.Ciphertext {
	keyTmp := make([]uint64, b.Halfslots()+pasta.T)

	for i := 0; i < pasta.T; i++ {
		secondHalf := i + int(b.Halfslots())

		keyTmp[i] = secretKey[i]
		keyTmp[secondHalf] = secretKey[i+pasta.T]
	}
	plaintext := bfv.NewPlaintext(b.Params, b.Params.MaxLevel())
	b.Encoder.Encode(keyTmp, plaintext)

	return b.Encrypt(plaintext)
}

func (b *BFV) Slots() uint64 {
	return uint64(b.Params.N())
}

func (b *BFV) Halfslots() uint64 {
	return b.Slots() / 2
}

func (b *BFV) WithRelinKeys(relinearizationKeyBytes []byte, parameters bfv.Parameters) {
	// create evaluator with relinearization keys
	rk := rlwe.NewRelinearizationKey(parameters.Parameters)
	rk.UnmarshalBinary(relinearizationKeyBytes)
	b.Evk.RelinearizationKey = rk
	b.Evaluator = b.Evaluator.WithKey(&b.Evk)
}

func (b *BFV) WithGalEls(els []uint64, rk *rlwe.RelinearizationKey, sk rlwe.SecretKey) {
	evks := Genevk(b.Params.Parameters, els, &sk, rk)
	b.Evk.RelinearizationKey = evks.RelinearizationKey
	b.Evk.GaloisKeys = evks.GaloisKeys
	b.Evaluator = b.Evaluator.WithKey(evks)
}
