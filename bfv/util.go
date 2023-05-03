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
	secretKey rlwe.SecretKey
}

func NewUtil(bfvParams bfv.Parameters, encoder bfv.Encoder, evaluator bfv.Evaluator, keygen rlwe.KeyGenerator,
	secretKey rlwe.SecretKey) Util {
	return Util{bfvParams, encoder, evaluator, keygen, secretKey}
}

func NewUtilByCipher(bfvCipher BFVCipher, secretKey rlwe.SecretKey) Util {
	return NewUtil(bfvCipher.bfvParams, bfvCipher.Encoder,
		bfvCipher.Evaluator, bfvCipher.Keygen, secretKey)
}

func (u *Util) AddRc(state *rlwe.Ciphertext, rc []uint64) *rlwe.Ciphertext {
	roundConstants := bfv.NewPlaintext(u.bfvParams, state.Level())
	u.encoder.Encode(rc, roundConstants)
	return u.evaluator.AddNew(state, roundConstants)
}

func (u *Util) Mix(state *rlwe.Ciphertext) *rlwe.Ciphertext {
	stateOriginal := state.CopyNew()
	tmp := u.evaluator.RotateRowsNew(state)
	tmp = u.evaluator.AddNew(tmp, stateOriginal)
	return u.evaluator.AddNew(stateOriginal, tmp)
}

func (u *Util) SboxCube(state *rlwe.Ciphertext) *rlwe.Ciphertext {
	s := state.CopyNew()
	state = u.evaluator.MulNew(state, state)  // ^ 2
	state = u.evaluator.RelinearizeNew(state) // ciphertext X ciphertext -> relinearization
	state = u.evaluator.MulNew(state, s)      // ^ 3
	state = u.evaluator.RelinearizeNew(state) // ciphertext X ciphertext -> relinearization
	return state
}

func (u *Util) SboxFeistel(state *rlwe.Ciphertext, halfslots uint64) *rlwe.Ciphertext {
	originalState := state.CopyNew()

	// rotate state
	stateRot := u.evaluator.RotateColumnsNew(state, -1)

	// mask rotate state
	mask := bfv.NewPlaintext(u.bfvParams, state.Level())
	maskVec := make([]uint64, pasta.T+halfslots)
	for i := range maskVec {
		maskVec[i] = 1
	}
	maskVec[0] = 0
	maskVec[halfslots] = 0
	for i := uint64(pasta.T); i < halfslots; i++ {
		maskVec[i] = 0
	}
	u.encoder.Encode(maskVec, mask)
	stateRot = u.evaluator.MulNew(stateRot, mask) // no need to relinearize because it's been multiplied by a plain
	// stateRot = 0, x_1, x_2, x_3, .... x_(t-1)

	// square
	state = u.evaluator.MulNew(stateRot, stateRot)
	state = u.evaluator.RelinearizeNew(state) // needs relinearization
	// stateRot = 0, x_1^2, x_2^2, x_3^2, .... x_(t-1)^2

	result := u.evaluator.AddNew(originalState, state)
	// state = x_1, x_1^2 + x_2, x_2^2 + x_3, x_3^2 + x_4, .... x_(t-1)^2 + x_t

	return result
}

func (u *Util) Matmul(state *rlwe.Ciphertext, mat1, mat2 [][]uint64, slots, halfslots uint64) *rlwe.Ciphertext {
	// todo(fedejinich) this is actually not working but it will be added in the future
	//if useBsGs {
	//	return u.babyStepGiantStep(state, mat1, mat2, slots, halfslots)
	//}
	return u.diagonal(*state, mat1, mat2, int(slots), int(halfslots))
}

func (u *Util) diagonal(state rlwe.Ciphertext, mat1, mat2 [][]uint64, slots, halfslots int) *rlwe.Ciphertext {
	matrixDim := pasta.T

	if matrixDim*2 != slots && matrixDim*4 > slots {
		fmt.Println("too little slots for matmul implementation!")
		fmt.Errorf("too little slots for matmul implementation!")
	}

	// non-full-packed rotation preparation
	if halfslots != matrixDim {
		stateRot := u.evaluator.RotateColumnsNew(&state, matrixDim)
		state = *u.evaluator.AddNew(&state, stateRot)
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
		row := u.encoder.EncodeNew(diag, u.bfvParams.MaxLevel())
		matrix[i] = *row
	}

	sum := state.CopyNew()
	sum = u.evaluator.MulNew(sum, &matrix[0]) // ciphertext X plaintext, no need relin
	for i := 1; i < matrixDim; i++ {
		state = *u.evaluator.RotateColumnsNew(&state, -1)
		tmp := u.evaluator.MulNew(&state, &matrix[i]) // ciphertext X plaintext, no need relin
		sum = u.evaluator.AddNew(sum, tmp)
	}

	return sum
}

func (u *Util) Flatten(decomp []rlwe.Ciphertext, plainSize int, evaluator bfv.Evaluator) rlwe.Ciphertext {
	ciphertext := decomp[0]
	for i := 1; i < len(decomp); i++ {
		tmp := evaluator.RotateColumnsNew(&decomp[i], -(i * plainSize))
		ciphertext = *evaluator.AddNew(&ciphertext, tmp)
	}

	return ciphertext
}

func (u *Util) Mask(decomp []rlwe.Ciphertext, mask []uint64, params bfv.Parameters, encoder bfv.Encoder, evaluator bfv.Evaluator) []rlwe.Ciphertext {
	lastIndex := len(decomp) - 1
	last := decomp[lastIndex]
	plaintext := bfv.NewPlaintext(params, last.Level()) // halfslots
	encoder.Encode(mask, plaintext)
	decomp[lastIndex] = *evaluator.MulNew(&last, plaintext) // no needs relinearization

	return decomp
}

// GenerateEvaluationKeys create keys for rotations and relinearization
func (u *Util) GenerateEvaluationKeys(matrixSize uint64, plainSize uint64, modDegree uint64, useBsGs bool,
	bsGsN2 uint64, bsGsN1 uint64, reminder uint64) rlwe.EvaluationKey {
	// first we create the right galois indexes to define the right rotations steps (whether for columns or rows)

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
	return genEVK(gkIndices, u.bfvParams.Parameters, u.keygen, &u.secretKey)
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

func RandomInputV(N int, plainMod uint64) []uint64 {
	rand.Seed(time.Now().UnixNano())
	vi := make([]uint64, 0, N)
	for i := 0; i < N; i++ {
		vi = append(vi, rand.Uint64()%plainMod) // not cryptosecure ;)
	}
	return vi
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
//		r := bfv.NewPlaintext(u.bfvParams, state.Level())
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
//				outerSum = *rlwe.NewCiphertext(u.bfvParams.Parameters, innerSum.Degree(), innerSum.Level())
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
