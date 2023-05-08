package bfv

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"hhego/pasta"
	"math/rand"
	"time"
)

// BsgsN1 used for babystep-gigantstep
const BsgsN1 = 16

// BsgsN2 used for babystep-gigantstep
const BsgsN2 = 8

type Util struct {
	bfvParams bfv.Parameters
	encoder   bfv.Encoder
	evaluator bfv.Evaluator
	keygen    rlwe.KeyGenerator
}

func NewUtil(bfvParams bfv.Parameters, encoder bfv.Encoder, evaluator bfv.Evaluator, keygen rlwe.KeyGenerator) Util {
	return Util{bfvParams, encoder, evaluator, keygen}
}

func AddRc(state *rlwe.Ciphertext, rc []uint64, encoder bfv.Encoder, evaluator bfv.Evaluator, bfvParams bfv.Parameters) *rlwe.Ciphertext {
	roundConstants := bfv.NewPlaintext(bfvParams, state.Level())
	encoder.Encode(rc, roundConstants)
	return evaluator.AddNew(state, roundConstants) // ct + pt
}

func Mix(state *rlwe.Ciphertext, evaluator bfv.Evaluator, encoder bfv.Encoder) *rlwe.Ciphertext {
	stateOriginal := state.CopyNew()
	tmp := evaluator.RotateRowsNew(state)
	tmp = evaluator.AddNew(tmp, stateOriginal)
	return evaluator.AddNew(stateOriginal, tmp)
}

func SboxCube(state *rlwe.Ciphertext, evaluator bfv.Evaluator) *rlwe.Ciphertext {
	s := state.CopyNew()
	state = evaluator.MulNew(state, state) // ^ 2 ct x ct -> relinearization
	state = evaluator.RelinearizeNew(state)
	state = evaluator.MulNew(state, s) // ^ 3  ct x ct -> relinearization
	state = evaluator.RelinearizeNew(state)
	return state
}

func SboxFeistel(state *rlwe.Ciphertext, halfslots uint64, evaluator bfv.Evaluator,
	encoder bfv.Encoder, bfvParams bfv.Parameters) *rlwe.Ciphertext {
	originalState := state.CopyNew()

	// rotate state
	stateRot := evaluator.RotateColumnsNew(state, -1)

	// mask rotate state
	mask := bfv.NewPlaintext(bfvParams, state.Level())
	maskVec := make([]uint64, pasta.T+halfslots)
	for i := range maskVec {
		maskVec[i] = 1
	}
	maskVec[0] = 0
	maskVec[halfslots] = 0
	for i := uint64(pasta.T); i < halfslots; i++ {
		maskVec[i] = 0
	}
	encoder.Encode(maskVec, mask)
	stateRot = evaluator.MulNew(stateRot, mask) // ct x pt

	// square
	state = evaluator.MulNew(stateRot, stateRot)
	state = evaluator.RelinearizeNew(state) // ct x ct -> relinearization

	// add
	result := evaluator.AddNew(originalState, state)

	return result
}

func Matmul(state *rlwe.Ciphertext, mat1, mat2 [][]uint64, slots, halfslots uint64, evaluator bfv.Evaluator, encoder bfv.Encoder, bfvParams bfv.Parameters) *rlwe.Ciphertext {
	// todo(fedejinich) this is actually not working but it will be added in the future
	//if useBsGs {
	//	return u.babyStepGiantStep(state, mat1, mat2, slots, halfslots)
	//}
	return diagonal(*state, mat1, mat2, int(slots), int(halfslots), evaluator, encoder, bfvParams)
}

func diagonal(state rlwe.Ciphertext, mat1, mat2 [][]uint64, slots, halfslots int, evaluator bfv.Evaluator, encoder bfv.Encoder, bfvParams bfv.Parameters) *rlwe.Ciphertext {
	matrixDim := pasta.T

	if matrixDim*2 != slots && matrixDim*4 > slots {
		fmt.Println("too little slots for matmul implementation!")
		fmt.Errorf("too little slots for matmul implementation!")
	}

	// non-full-packed rotation preparation
	if halfslots != matrixDim {
		stateRot := evaluator.RotateColumnsNew(&state, matrixDim)
		state = *evaluator.AddNew(&state, stateRot)
	}

	// diagonal method preperation:
	matrix := make([]rlwe.Plaintext, matrixDim)
	for i := 0; i < matrixDim; i++ {
		diag := make([]uint64, matrixDim+halfslots)
		for t := 0; t < len(diag); t++ {
			diag[t] = 0
		}

		for j := 0; j < matrixDim; j++ {
			diag[j] = mat1[j][(j+matrixDim-i)%matrixDim]
			diag[j+halfslots] = mat2[j][(j+matrixDim-i)%matrixDim]
		}
		row := encoder.EncodeNew(diag, bfvParams.MaxLevel())
		matrix[i] = *row
	}

	sum := state.CopyNew()
	sum = evaluator.MulNew(sum, &matrix[0]) // ciphertext X plaintext, no need relin
	for i := 1; i < matrixDim; i++ {
		state = *evaluator.RotateColumnsNew(&state, -1)
		tmp := evaluator.MulNew(&state, &matrix[i]) // ciphertext X plaintext, no need relin
		sum = evaluator.AddNew(sum, tmp)
	}

	return sum
}

// PostProcess creates and applies a masking vector and flattens transciphered pasta blocks into one ciphertext
func PostProcess(decomp []rlwe.Ciphertext, plainSize, matrixSize uint64, evaluator bfv.Evaluator, encoder bfv.Encoder, bfvParams bfv.Parameters) rlwe.Ciphertext {
	reminder := reminder(matrixSize, plainSize)

	if reminder != 0 {
		mask := make([]uint64, reminder) // create a 1s mask
		for i := range mask {
			mask[i] = 1
		}
		lastIndex := len(decomp) - 1
		last := decomp[lastIndex]
		plaintext := bfv.NewPlaintext(bfvParams, last.Level()) // halfslots
		encoder.Encode(mask, plaintext)
		// mask
		decomp[lastIndex] = *evaluator.MulNew(&last, plaintext) // ct x pt
	}

	// flatten ciphertexts
	ciphertext := decomp[0]
	for i := 1; i < len(decomp); i++ {
		tmp := evaluator.RotateColumnsNew(&decomp[i], -(i * int(plainSize)))
		ciphertext = *evaluator.AddNew(&ciphertext, tmp) // ct + ct
	}

	return ciphertext
}

func reminder(matrixSize uint64, plainSize uint64) uint64 {
	return matrixSize % plainSize
}

func RandomInputV(N int, plainMod uint64) []uint64 {
	rand.Seed(time.Now().UnixNano())
	vi := make([]uint64, 0, N)
	for i := 0; i < N; i++ {
		vi = append(vi, rand.Uint64()%plainMod) // not cryptosecure ;)
	}
	return vi
}

// EvaluationKeysBfvPasta creates galois keys (for rotations and relinearization) to transcipher from pasta to bfv
func EvaluationKeysBfvPasta(matrixSize uint64, plainSize uint64, modDegree uint64, useBsGs bool,
	bsGsN2 uint64, bsGsN1 uint64, secretKey rlwe.SecretKey, bfvParams bfv.Parameters, keygen rlwe.KeyGenerator) rlwe.EvaluationKey {
	reminder := reminder(matrixSize, plainSize)

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

func BasicEvaluationKeys(parameters rlwe.Parameters, keygen rlwe.KeyGenerator, key *rlwe.SecretKey) rlwe.EvaluationKey {
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

//func (u *Util) babyStepGiantStep(state *rlwe.Ciphertext, mat1 [][]uint64, mat2 [][]uint64, slots, halfslots uint64) *rlwe.Ciphertext {
//	matrixDim := pasta.T
//
//	if ((matrixDim * 2) != int(slots)) && ((matrixDim * 4) > int(halfslots)) {
//		fmt.Println("too little slots for matmul implementation!")
//	}
//
//	if BsgsN1*BsgsN2 != matrixDim {
//		fmt.Println("wrong bsgs params")
//	}
//
//	// diagonal method preperation:
//	matrix := make([]rlwe.Plaintext, matrixDim)
//	aux := make([][]uint64, matrixDim)
//	for i := 0; i < matrixDim; i++ {
//		diag := make([]uint64, matrixDim)
//		tmp := make([]uint64, matrixDim)
//
//		k := uint64(i / BsgsN1)
//
//		for j := 0; j < matrixDim; j++ {
//			diag[j] = mat1[j][(j+matrixDim-i)%matrixDim] // push back
//			tmp[j] = mat2[j][(j+matrixDim-i)%matrixDim]  // push back
//		}
//
//		// rotate:
//		if k != 0 {
//			util.Rotate(diag[0], diag[0]+(uint64(k)*BsgsN1), diag[len(diag)-1], diag) // todo(fedejinich) not sure about using this method
//			util.Rotate(tmp[0], tmp[0]+(uint64(k)*BsgsN1), tmp[len(tmp)-1], tmp)      // todo(fedejinich) not sure about using this method
//		}
//
//		// prepare for non-full-packed rotations
//		if halfslots != pasta.T {
//			newSize := int(halfslots)
//			diag = resize(diag, newSize, 0)
//			tmp = resize(tmp, newSize, 0)
//			for m := uint64(0); m < k*BsgsN1; m++ {
//				indexSrc := pasta.T - 1 - m
//				indexDest := halfslots - 1 - m
//				diag[indexDest] = diag[indexSrc]
//				diag[indexSrc] = 0
//				tmp[indexDest] = tmp[indexSrc]
//				tmp[indexSrc] = 0
//			}
//		}
//
//		// combine both diags
//		diag = resize(diag, int(slots), 0)
//		for j := halfslots; j < slots; j++ {
//			diag[j] = tmp[j-halfslots]
//		}
//
//		r := bfv.NewPlaintext(u.Params, state.Level())
//		u.encoder.Encode(diag, r)
//		matrix[i] = *r // push back
//		aux[i] = diag  // for debug todo(fedejinich) remove this
//	}
//
//	// prepare for non-full-packed rotations
//	if halfslots != pasta.T {
//		s := state.CopyNew()
//		stateRot := u.evaluator.RotateColumnsNew(s, pasta.T)
//		state = u.evaluator.AddNew(state, stateRot)
//	}
//
//	// prepare rotations
//	rot := make([]rlwe.Ciphertext, BsgsN1)
//	rot[0] = *state
//	for j := 1; j < BsgsN1; j++ {
//		rot[j] = *u.evaluator.RotateColumnsNew(&rot[j-1], -1)
//	}
//
//	var outerSum rlwe.Ciphertext
//	for k := 0; k < BsgsN2; k++ {
//		fmt.Sprintf("%v\n", k)
//		innerSum := u.evaluator.MulNew(&rot[0], &matrix[k*BsgsN1]) // no needs relinearization
//		for j := 1; j < BsgsN1; j++ {
//			temp := u.evaluator.MulNew(&rot[j], &matrix[k*BsgsN1+j]) // no needs relinearization
//			u.evaluator.Add(innerSum, temp, innerSum)
//		}
//		if k != 0 {
//			outerSum = *innerSum
//		} else {
//			if outerSum.Value == nil { // todo(fedejinich) this is not ideal
//				outerSum = *rlwe.NewCiphertext(u.Params.Parameters, innerSum.Degree(), innerSum.Level())
//			}
//			u.evaluator.RotateColumns(innerSum, -k*BsgsN1, innerSum)
//			outerSum = *u.evaluator.AddNew(&outerSum, innerSum)
//		}
//	}
//
//	return &outerSum
//}
//
//func resize(slice []uint64, newSize int, value uint64) []uint64 {
//	initSize := len(slice)
//	if initSize >= newSize {
//		return slice[:newSize]
//	}
//
//	newSlice := make([]uint64, newSize)
//	for i := 0; i < newSize; i++ {
//		if i < initSize {
//			newSlice[i] = slice[i]
//		} else {
//			newSlice[i] = value
//		}
//	}
//
//	return newSlice
//}
