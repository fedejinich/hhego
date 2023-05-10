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
	pastaSeclevel  uint64 // pasta secret key security level (usually 128bits)
	bfvPastaParams PastaParams
	slots          uint64 // determined by the polynomial modulus degree of the encryption parameters
}

type PastaParams struct {
	PastaRounds         int
	PastaCiphertextSize int
	Modulus             int
}

func NewBFV(bfvParams bfv.Parameters, secretKey *rlwe.SecretKey, evaluator bfv.Evaluator, encoder bfv.Encoder,
	bfvPastaParams PastaParams, keygen rlwe.KeyGenerator, slots, matrixSize, pastaSeclevel uint64) BFV {
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
		pastaSeclevel,
		bfvPastaParams,
		slots,
	}
}

func NewBFVPasta(pastaParams PastaParams, modDegree, pastaSeclevel, matrixSize, bsGsN1, bsGsN2 uint64,
	useBsGs bool, plainMod uint64) BFV {
	bfvParams := GenerateBfvParams(plainMod, modDegree)
	keygen := bfv.NewKeyGenerator(bfvParams)
	secretKey, _ := keygen.GenKeyPair()
	bfvEncoder := bfv.NewEncoder(bfvParams)
	evk := EvaluationKeysBfvPasta(matrixSize, pastaSeclevel, modDegree, useBsGs,
		bsGsN2, bsGsN1, *secretKey, bfvParams, keygen)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, evk)

	bfvCipher := NewBFV(bfvParams, secretKey, bfvEvaluator, bfvEncoder,
		pastaParams, keygen, modDegree, matrixSize, pastaSeclevel)

	return bfvCipher
}

func GenerateBfvParams(modulus uint64, degree uint64) bfv.Parameters {
	var bfvParams bfv.ParametersLiteral
	if degree == uint64(math.Pow(2, 15)) {
		fmt.Println("polynomial modDegree = 2^15 (32768)")
		bfvParams = bfv.PN15QP827pq // post-quantum params
	} else if degree == uint64(math.Pow(2, 16)) {
		fmt.Println("polynomial modDegree = 2^16 (65536)")
		bfvParams.LogN = 16
		bfvParams.Q = []uint64{0xffffffffffc0001, 0xfffffffff840001, 0xfffffffff6a0001,
			0xfffffffff5a0001, 0xfffffffff2a0001, 0xfffffffff240001,
			0xffffffffefe0001, 0xffffffffeca0001, 0xffffffffe9e0001,
			0xffffffffe7c0001, 0xffffffffe740001, 0xffffffffe520001,
			0xffffffffe4c0001, 0xffffffffe440001, 0xffffffffe400001,
			0xffffffffdda0001, 0xffffffffdd20001, 0xffffffffdbc0001,
			0xffffffffdb60001, 0xffffffffd8a0001, 0xffffffffd840001,
			0xffffffffd6e0001, 0xffffffffd680001, 0xffffffffd2a0001,
			0xffffffffd000001, 0xffffffffcf00001, 0xffffffffcea0001,
			0xffffffffcdc0001, 0xffffffffcc40001} // 1740 bits
		bfvParams.P = []uint64{}
	} else if degree == uint64(math.Pow(2, 14)) {
		fmt.Println("polynomial modDegree = 2^14 (16384)")
		bfvParams = bfv.PN14QP411pq // post-quantum params
	} else {
		panic(fmt.Sprintf("polynomial modDegree not supported (modDegree)"))
	}
	bfvParams.T = modulus

	params, err := bfv.NewParametersFromLiteral(bfvParams)
	if err != nil {
		panic(fmt.Sprintf("couldn't initialize bfvParams"))
	}

	return params
}

func NewBFVBasic(pastaParams PastaParams, modulus, degree uint64) (BFV, Util) {
	bfvParams := GenerateBfvParams(modulus, degree)
	keygen := bfv.NewKeyGenerator(bfvParams)
	s, _ := keygen.GenKeyPair()
	evk := BasicEvaluationKeys(bfvParams.Parameters, keygen, s)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, evk)
	bfvEncoder := bfv.NewEncoder(bfvParams)

	bfv := NewBFV(bfvParams, s, bfvEvaluator, bfvEncoder, pastaParams, keygen, degree, 0, 0)

	return bfv, bfv.Util
}

func (b *BFV) Encrypt(plaintext *rlwe.Plaintext) *rlwe.Ciphertext {
	return b.encryptor.EncryptNew(plaintext)
}

func (b *BFV) Transcipher(encryptedMessage []uint64, pastaSecretKey *rlwe.Ciphertext) rlwe.Ciphertext {
	pastaUtil := pasta.NewUtil(nil, uint64(b.bfvPastaParams.Modulus), b.bfvPastaParams.PastaRounds)

	encryptedMessageLength := float64(len(encryptedMessage))

	numBlock := pastaUtil.BlockCount(encryptedMessageLength, float64(b.bfvPastaParams.PastaCiphertextSize))

	result := make([]rlwe.Ciphertext, numBlock) // each element represents a pasta decrypted block
	for block := 0; block < numBlock; block++ {
		pastaUtil.InitShake(pasta.Nonce, uint64(block))

		// 'state' contains the two PASTA branches encoded as b.ciphertext
		// s1 := pastaSecretKey[0:halfslots]
		// s1 := pastaSecretKey[:halfslots]
		state := pastaSecretKey

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

	return PostProcess(result, b.pastaSeclevel, b.matrixSize, b.Evaluator, b.Encoder, b.Params)
}

func (b *BFV) Decrypt(ciphertext *rlwe.Ciphertext) *rlwe.Plaintext {
	return b.decryptor.DecryptNew(ciphertext)
}

func (b *BFV) DecryptPacked(ciphertext *rlwe.Ciphertext, matrixSize uint64) []uint64 {
	plaintext := b.decryptor.DecryptNew(ciphertext)
	dec := b.Encoder.DecodeUintNew(plaintext)

	return dec[0:matrixSize] // todo(fedejinich) this can be improved to dec[:matrixSize]
}

func (b *BFV) EncryptPastaSecretKey(secretKey []uint64) *rlwe.Ciphertext {
	keyTmp := make([]uint64, b.Halfslots()+pasta.T)

	for i := 0; i < pasta.T; i++ {
		secondHalf := i + int(b.Halfslots())

		keyTmp[i] = secretKey[i]
		keyTmp[secondHalf] = secretKey[i+pasta.T]
	}
	plaintext := b.Encoder.EncodeNew(keyTmp, b.Params.MaxLevel())

	return b.Encrypt(plaintext)
}

func (b *BFV) Halfslots() uint64 {
	return b.slots / 2
}

func (b *BFV) PackedAffine(M [][]uint64, v rlwe.Ciphertext, bi []uint64) rlwe.Ciphertext {
	vo := b.packedMatMul(M, v)
	p := b.Encoder.EncodeNew(bi, b.Params.MaxLevel())
	return *b.Evaluator.AddNew(&vo, p)
}

func (b *BFV) packedMatMul(M [][]uint64, v rlwe.Ciphertext) rlwe.Ciphertext {
	vo := v.CopyNew()
	return b.packedDiagonal(vo, M)
}

func (b *BFV) packedDiagonal(v *rlwe.Ciphertext, M [][]uint64) rlwe.Ciphertext {
	matrixDim := uint64(len(M))
	nslots := b.slots

	if matrixDim*2 != nslots && matrixDim*4 > nslots {
		panic("too little slots for matmul implementation!")
	}

	// non-full-packed rotation preparation
	if nslots != matrixDim*2 {
		vRot := b.Evaluator.RotateColumnsNew(v, -int(matrixDim))
		v = b.Evaluator.AddNew(v, vRot)
	}

	// diagonal method preperation:
	matrix := make([]rlwe.Plaintext, matrixDim)
	for i := 0; uint64(i) < matrixDim; i++ {
		diag := make([]uint64, matrixDim)
		for j := 0; uint64(j) < matrixDim; j++ {
			diag[j] = M[j][(uint64(i+j) % matrixDim)]
		}
		row := b.Encoder.EncodeNew(diag, b.Params.MaxLevel())
		matrix[i] = *row
	}

	sum := v.CopyNew()
	sum = b.Evaluator.MulNew(sum, &matrix[0])
	for i := 0; uint64(i) < matrixDim; i++ {
		tmp := b.Evaluator.RotateColumnsNew(v, 1)
		tmp = b.Evaluator.MulNew(tmp, &matrix[i])
		sum = b.Evaluator.AddNew(tmp, sum)
	}

	return *sum
}

func (b *BFV) PackedSquare(ciphertext rlwe.Ciphertext) rlwe.Ciphertext {
	r := b.Evaluator.MulNew(&ciphertext, &ciphertext)
	return *b.Evaluator.RelinearizeNew(r)
}

func (b *BFV) DecryptResult(ciphertext *rlwe.Ciphertext) []uint64 {
	p := b.Decrypt(ciphertext)
	d := b.Encoder.DecodeUintNew(p)

	return d[:b.matrixSize]
}
