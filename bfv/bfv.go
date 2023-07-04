package bfv

import (
	"fmt"
	"github.com/fedejinich/hhego/pasta"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
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
	//matrixSize     uint64 // size of the pasta-bfv decryption matrix
	//pastaSeclevel  uint64 // pasta secret key security level (usually 128bits)
	//bfvPastaParams PastaParams
	slots uint64 // determined by the polynomial modulus degree of the encryption parameters
}

type PastaParams struct {
	PastaRounds         int
	PastaCiphertextSize int
	Modulus             int
}

func NewBFV(bfvParams bfv.Parameters, secretKey *rlwe.SecretKey, evaluator bfv.Evaluator, encoder bfv.Encoder,
	keygen rlwe.KeyGenerator, slots uint64) BFV {
	return BFV{
		bfv.NewEncryptor(bfvParams, secretKey),
		bfv.NewDecryptor(bfvParams, secretKey),
		evaluator,
		encoder,
		keygen,
		bfvParams,
		*secretKey,
		NewUtil(bfvParams, encoder, evaluator, keygen),
		slots,
	}
}

func NewBFVPastaCipher(modDegree, pastaSeclevel, matrixSize, bsGsN1, bsGsN2 uint64, useBsGs bool, plainMod uint64) BFV {
	bfvParams := generateBfvParams(plainMod, modDegree)
	keygen := bfv.NewKeyGenerator(bfvParams)
	secretKey, _ := keygen.GenKeyPairNew()
	bfvEncoder := bfv.NewEncoder(bfvParams)
	evk := EvaluationKeysBfvPasta(matrixSize, pastaSeclevel, modDegree, useBsGs,
		bsGsN2, bsGsN1, *secretKey, bfvParams, *keygen)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, &evk)

	bfvCipher := NewBFV(bfvParams, secretKey, bfvEvaluator, bfvEncoder, *keygen, modDegree)

	return bfvCipher
}

func generateBfvParams(modulus uint64, degree uint64) bfv.Parameters {
	var bfvParams bfv.ParametersLiteral
	if degree == uint64(math.Pow(2, 14)) {
		fmt.Println("polynomial modDegree (LogN) = 2^14 (16384)")
		bfvParams = bfv.PN14QP411pq // post-quantum params
	} else if degree == uint64(math.Pow(2, 15)) {
		fmt.Println("polynomial modDegree (LogN) = 2^15 (32768)")
		bfvParams = bfv.PN15QP827pq // post-quantum params
	} else if degree == uint64(math.Pow(2, 16)) {
		fmt.Println("polynomial modDegree (LogN) = 2^16 (65536)")
		bfvParams = bfv.ParametersLiteral{
			LogN: 16,
			T:    0xffffffffffc0001,
			Q: []uint64{0x10000000006e0001,
				0xfffffffff840001,
				0x1000000000860001,
				0xfffffffff6a0001,
				0x1000000000980001,
				0xfffffffff5a0001,
				0x1000000000b00001,
				0x1000000000ce0001,
				0xfffffffff2a0001,
				0xfffffffff240001,
				0x1000000000f00001,
				0xffffffffefe0001,
				0x10000000011a0001,
				0xffffffffeca0001,
				0xffffffffe9e0001,
				0xffffffffe7c0001,
				0xffffffffe740001,
				0x10000000019a0001,
				0x1000000001a00001,
				0xffffffffe520001,
				0xffffffffe4c0001,
				0xffffffffe440001,
				0x1000000001be0001,
				0xffffffffe400001},
			P: []uint64{0x1fffffffffe00001,
				0x1fffffffffc80001,
				0x2000000000460001,
				0x1fffffffffb40001,
				0x2000000000500001},
		}
	} else {
		panic(fmt.Sprintf("polynomial modDegree not supported (modDegree)"))
	}

	fmt.Println(fmt.Sprintf("modulus (T) = %d", modulus))
	bfvParams.T = modulus

	params, err := bfv.NewParametersFromLiteral(bfvParams)
	if err != nil {
		panic(fmt.Sprintf("couldn't initialize bfvParams"))
	}

	return params
}

func NewBFVBasicCipher(pastaParams PastaParams, modulus, degree uint64, matrixSize uint64) (BFV, Util) {
	bfvParams := generateBfvParams(modulus, degree)
	keygen := bfv.NewKeyGenerator(bfvParams)
	s, _ := keygen.GenKeyPairNew()
	evk := BasicEvaluationKeys(bfvParams.Parameters, *keygen, s)
	bfvEvaluator := bfv.NewEvaluator(bfvParams, &evk)
	bfvEncoder := bfv.NewEncoder(bfvParams)

	cipher := NewBFV(bfvParams, s, bfvEvaluator, bfvEncoder, *keygen, degree)

	return cipher, cipher.Util
}

func (b *BFV) Encrypt(plaintext *rlwe.Plaintext) *rlwe.Ciphertext {
	return b.encryptor.EncryptNew(plaintext)
}

func (b *BFV) Transcipher(encryptedMessage []uint64, pastaSecretKey *rlwe.Ciphertext, useBsGs bool, bfvPastaParams PastaParams, pastaSeclevel uint64, matrixSize uint64) rlwe.Ciphertext {
	pastaUtil := pasta.NewUtil(nil, uint64(bfvPastaParams.Modulus), bfvPastaParams.PastaRounds)

	encryptedMessageLength := float64(len(encryptedMessage))

	numBlock := pastaUtil.BlockCount(encryptedMessageLength, float64(bfvPastaParams.PastaCiphertextSize))

	fmt.Printf("Transciphering %d pasta blocks\n", numBlock)

	result := make([]rlwe.Ciphertext, numBlock) // each element represents a pasta decrypted block
	for block := 0; block < numBlock; block++ {
		pastaUtil.InitShake(pasta.Nonce, uint64(block))

		// 'state' contains the two PASTA branches encoded as b.ciphertext
		// s1 := pastaSecretKey[0:halfslots]
		// s2 := pastaSecretKey[:halfslots]
		state := pastaSecretKey

		fmt.Printf("block %d/%d\n", block, numBlock)

		for r := 1; r <= bfvPastaParams.PastaRounds; r++ {
			fmt.Printf("round %d\n", r)

			mat1 := pastaUtil.RandomMatrix()
			mat2 := pastaUtil.RandomMatrix()
			rc := pastaUtil.RCVec(b.Halfslots())

			state = Matmul(state, mat1, mat2, b.slots, b.Halfslots(), b.Evaluator, b.Encoder, b.Params, useBsGs)
			state = AddRc(state, rc, b.Encoder, b.Evaluator, b.Params)
			state = Mix(state, b.Evaluator, b.Encoder)

			if r == bfvPastaParams.PastaRounds {
				state = SboxCube(state, b.Evaluator)
			} else {
				state = SboxFeistel(state, b.Halfslots(), b.Evaluator, b.Encoder, b.Params)
			}
		}

		fmt.Println("final add")

		mat1 := pastaUtil.RandomMatrix()
		mat2 := pastaUtil.RandomMatrix()
		rc := pastaUtil.RCVec(b.Halfslots())

		state = Matmul(state, mat1, mat2, b.slots, b.Halfslots(), b.Evaluator, b.Encoder, b.Params, useBsGs)
		state = AddRc(state, rc, b.Encoder, b.Evaluator, b.Params)
		state = Mix(state, b.Evaluator, b.Encoder)

		// add cipher
		start := 0 + (block * bfvPastaParams.PastaCiphertextSize)
		end := math.Min(float64((block+1)*bfvPastaParams.PastaCiphertextSize), encryptedMessageLength)
		cipherTmp := encryptedMessage[start:int(end)]

		plaintext := bfv.NewPlaintext(b.Params, b.Params.MaxLevel())
		b.Encoder.Encode(cipherTmp, plaintext)
		state = b.Evaluator.NegNew(state)
		result[block] = *b.Evaluator.AddNew(state, plaintext) // ct + pt
	}

	return PostProcess(result, pastaSeclevel, matrixSize, b.Evaluator, b.Encoder, b.Params)
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

func (b *BFV) Halfslots() uint64 {
	return b.slots / 2
}

// todo(fedejinich) to be honest, this code is not relevant and will be removed. It's useful for a specific usecase
//  (training a NN with HE) and it's not relevant for blockchain applications
//func (b *BFV) PackedAffine(M [][]uint64, v rlwe.Ciphertext, bi []uint64) rlwe.Ciphertext {
//	vo := b.packedMatMul(M, v)
//	p := bfv.NewPlaintext(b.Params, b.Params.MaxLevel())
//	b.Encoder.Encode(bi, p)
//	return *b.Evaluator.AddNew(&vo, p)
//}
//
//func (b *BFV) packedMatMul(M [][]uint64, v rlwe.Ciphertext) rlwe.Ciphertext {
//	vo := v.CopyNew()
//	return *b.packedBabystepGigantStep(vo, M, b.slots)
//}
//
//func (b *BFV) packedBabystepGigantStep(ct *rlwe.Ciphertext, mat [][]uint64, slots uint64) *rlwe.Ciphertext {
//	// todo(fedejinich) tons of repeted code with bsgs
//	matrixDim := uint64(len(mat))
//	bsgsn1 := uint64(20)
//	bsgsn2 := uint64(10) // todo(fedejinich) hardcodeado hasta los huevos
//
//	if (matrixDim*2) != slots && (matrixDim*4) > slots {
//		panic("too little slots for matmul implementation!")
//	}
//
//	//if BsgsN1*BsgsN2 != matrixDim {
//	if bsgsn1*bsgsn2 != matrixDim {
//		panic("wrong bsgs parameters")
//	}
//
//	// diagonal method preparation
//	matrix := make([]*rlwe.Plaintext, matrixDim)
//	for i := uint64(0); i < matrixDim; i++ {
//		k := i / bsgsn1
//		diag := make([]uint64, matrixDim+k*bsgsn1)
//		for j := uint64(0); j < matrixDim; j++ {
//			diag[j] = mat[j][(j+i)%matrixDim]
//		}
//
//		// rotate:
//		if k > 0 {
//			diag = util.Rotate(diag, 0, k*bsgsn1, matrixDim) // only rotate filled elements
//		}
//
//		// prepare for non-full-packed rotations
//		if slots != matrixDim*2 {
//			for index := uint64(0); index < k*bsgsn1; index++ {
//				diag = append(diag, diag[index])
//				diag[index] = 0
//			}
//		}
//
//		row := bfv.NewPlaintext(b.Params, b.Params.MaxLevel())
//		b.Encoder.Encode(diag, row)
//		matrix[i] = row
//	}
//
//	// prepare for non-full-packed rotations
//	if slots != matrixDim*2 {
//		stateRot := b.Evaluator.RotateColumnsNew(ct, -int(matrixDim))
//		ct = b.Evaluator.AddNew(ct, stateRot)
//	}
//	rot := make([]*rlwe.Ciphertext, bsgsn1)
//	rot[0] = ct
//	for j := uint64(1); j < bsgsn1; j++ {
//		rot[j] = b.Evaluator.RotateColumnsNew(rot[j-1], -1)
//	}
//	// bsgs
//	var innerSum, outerSum, temp *rlwe.Ciphertext
//	for k := uint64(0); k < bsgsn2; k++ {
//		innerSum = b.Evaluator.MulNew(rot[0], matrix[k*bsgsn1])
//		for j := uint64(1); j < bsgsn1; j++ {
//			temp = b.Evaluator.MulNew(rot[j], matrix[k*bsgsn1+j])
//			innerSum = b.Evaluator.AddNew(innerSum, temp)
//		}
//		if k == 0 {
//			outerSum = innerSum
//		} else {
//			innerSum = b.Evaluator.RotateColumnsNew(innerSum, int(-k*bsgsn1))
//			outerSum = b.Evaluator.AddNew(outerSum, innerSum)
//		}
//	}
//
//	return outerSum
//}
//
//func (b *BFV) PackedSquare(ciphertext rlwe.Ciphertext) rlwe.Ciphertext {
//	r := b.Evaluator.MulNew(&ciphertext, &ciphertext)
//	return *b.Evaluator.RelinearizeNew(r)
//}
