package bfv

import (
	"fmt"
	util "github.com/fedejinich/hhego"
	"github.com/fedejinich/hhego/pasta"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
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
	roundConstants := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
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
	maskVec := make([]uint64, uint64(pasta.T)+halfslots)
	for i := range maskVec {
		maskVec[i] = 1
	}
	maskVec[0] = 0
	maskVec[halfslots] = 0
	for i := uint64(pasta.T); i < halfslots; i++ {
		maskVec[i] = 0
	}
	mask := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
	encoder.Encode(maskVec, mask)
	stateRot = evaluator.MulNew(stateRot, mask) // ct x pt

	// square
	state = evaluator.MulNew(stateRot, stateRot)
	state = evaluator.RelinearizeNew(state) // ct x ct -> relinearization

	// add
	result := evaluator.AddNew(originalState, state)

	return result
}

func Matmul(state *rlwe.Ciphertext, mat1, mat2 [][]uint64, slots, halfslots uint64, evaluator bfv.Evaluator,
	encoder bfv.Encoder, bfvParams bfv.Parameters, useBsGs bool) *rlwe.Ciphertext {
	if useBsGs {
		return babyStepGiantStep(state, mat1, mat2, slots, encoder, bfvParams, evaluator)
	}

	return diagonal(*state, mat1, mat2, int(slots), int(halfslots), evaluator, encoder, bfvParams)
}

func babyStepGiantStep(state *rlwe.Ciphertext, mat1 [][]uint64, mat2 [][]uint64, slots uint64, encoder bfv.Encoder,
	params bfv.Parameters, evaluator bfv.Evaluator) *rlwe.Ciphertext {

	halfslots := slots / 2
	matrixDim := uint64(pasta.T)

	if (matrixDim*2) != slots && (matrixDim*4) > slots {
		panic("too little slots for matmul implementation!")
	}

	if BsgsN1*BsgsN2 != matrixDim {
		panic("wrong bsgs parameters")
	}

	// diagonal method preparation
	matrix := make([]*rlwe.Plaintext, matrixDim)
	for i := uint64(0); i < matrixDim; i++ {
		diag := make([]uint64, halfslots+matrixDim)
		tmp := make([]uint64, matrixDim)
		k := i / BsgsN1
		for j := uint64(0); j < matrixDim; j++ {
			diag[j] = mat1[j][(j+matrixDim-i)%matrixDim]
			tmp[j] = mat2[j][(j+matrixDim-i)%matrixDim]
		}

		// rotate:
		if k > 0 {
			diag = util.Rotate(diag, 0, k*BsgsN1, matrixDim) // only rotate filled elements
			tmp = util.Rotate(tmp, 0, k*BsgsN1, matrixDim)
		}

		if halfslots != pasta.T {

			diag = resize(diag, halfslots)

			tmp = resize(tmp, halfslots)

			for m := uint64(0); m < k*BsgsN1; m++ {
				indexSrc := pasta.T - 1 - m
				indexDest := halfslots - 1 - m
				diag[indexDest] = diag[indexSrc]
				diag[indexSrc] = 0
				tmp[indexDest] = tmp[indexSrc]
				tmp[indexSrc] = 0
			}
		}
		// combine both diags

		diag = resize(diag, slots)

		for j := halfslots; j < slots; j++ {
			diag[j] = tmp[j-halfslots]
		}

		row := bfv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(diag, row)
		matrix[i] = row
	}

	// prepare for non-full-packed rotations
	if halfslots != pasta.T {
		stateRot := evaluator.RotateColumnsNew(state, pasta.T)
		state = evaluator.AddNew(state, stateRot)
	}
	rot := make([]*rlwe.Ciphertext, BsgsN1)
	rot[0] = state
	for j := 1; j < BsgsN1; j++ {
		rot[j] = evaluator.RotateColumnsNew(rot[j-1], -1)
	}
	// bsgs
	var innerSum, outerSum, temp *rlwe.Ciphertext
	for k := 0; k < BsgsN2; k++ {
		innerSum = evaluator.MulNew(rot[0], matrix[k*BsgsN1])
		for j := 1; j < BsgsN1; j++ {
			temp = evaluator.MulNew(rot[j], matrix[k*BsgsN1+j])
			innerSum = evaluator.AddNew(innerSum, temp)
		}
		if k == 0 {
			outerSum = innerSum
		} else {
			innerSum = evaluator.RotateColumnsNew(innerSum, -k*BsgsN1)
			outerSum = evaluator.AddNew(outerSum, innerSum)
		}
	}

	return outerSum
}

func resize(init []uint64, newSize uint64) []uint64 {
	if newSize == uint64(len(init)) {
		return init
	}

	if newSize < uint64(len(init)) {
		return init[0:newSize]
	}

	newSlice := make([]uint64, newSize) // new
	for i := 0; i < len(init); i++ {
		newSlice[i] = init[i]
	}

	return newSlice
}

func diagonal(state rlwe.Ciphertext, mat1, mat2 [][]uint64, slots, halfslots int, evaluator bfv.Evaluator,
	encoder bfv.Encoder, bfvParams bfv.Parameters) *rlwe.Ciphertext {

	matrixDim := pasta.T

	if matrixDim*2 != slots && matrixDim*4 > slots {
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
		for j := 0; j < matrixDim; j++ {
			diag[j] = mat1[j][(j+matrixDim-i)%matrixDim]
			diag[j+halfslots] = mat2[j][(j+matrixDim-i)%matrixDim]
		}
		row := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
		encoder.Encode(diag, row)
		matrix[i] = *row
	}

	sum := evaluator.MulNew(&state, &matrix[0]) // ciphertext X plaintext, no need relin
	for i := 1; i < matrixDim; i++ {
		state = *evaluator.RotateColumnsNew(&state, -1)
		tmp := evaluator.MulNew(&state, &matrix[i]) // ciphertext X plaintext, no need relin
		sum = evaluator.AddNew(sum, tmp)
	}

	return sum
}

// PostProcess creates and applies a masking vector and flattens transciphered pasta blocks into one ciphertext
func PostProcess(decomp []rlwe.Ciphertext, pastaSeclevel, matrixSize uint64, evaluator bfv.Evaluator, encoder bfv.Encoder,
	bfvParams bfv.Parameters) rlwe.Ciphertext {
	rem := reminder(matrixSize, pastaSeclevel)

	if rem != 0 {
		mask := make([]uint64, rem) // create a 1s mask
		for i := range mask {
			mask[i] = 1
		}
		lastIndex := len(decomp) - 1
		last := decomp[lastIndex].CopyNew()
		plaintext := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
		encoder.Encode(mask, plaintext)
		// mask
		decomp[lastIndex] = *evaluator.MulNew(last, plaintext) // ct x pt
	}

	// flatten ciphertexts
	ciphertext := decomp[0]
	// todo(fedejinich) this can be optimized PostProcessing at the end of the result add,
	//   in just one for loop
	for i := 1; i < len(decomp); i++ {
		tmp := evaluator.RotateColumnsNew(&decomp[i], -(i * int(pastaSeclevel)))
		ciphertext = *evaluator.AddNew(&ciphertext, tmp) // ct + ct
	}

	return ciphertext
}

func reminder(matrixSize uint64, pastaSeclevel uint64) uint64 {
	return matrixSize % pastaSeclevel
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
func EvaluationKeysBfvPasta(matrixSize uint64, pastaSeclevel uint64, modDegree uint64, useBsGs bool,
	bsGsN2 uint64, bsGsN1 uint64, secretKey rlwe.SecretKey, bfvParams bfv.Parameters, keygen rlwe.KeyGenerator) rlwe.EvaluationKeySet {
	rem := reminder(matrixSize, pastaSeclevel)

	numBlock := int64(matrixSize / pastaSeclevel)
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
		addDiagonalIndices(matrixSize, &gkIndices, modDegree)
	}

	// finally we create the right evaluation set (rotation & reliniarization keys)
	return *genEVK(gkIndices, bfvParams.Parameters, keygen, &secretKey)
}

func genEVK(gkIndices []int, params rlwe.Parameters, keygen rlwe.KeyGenerator, secretKey *rlwe.SecretKey) *rlwe.EvaluationKeySet {
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
	evk := rlwe.NewEvaluationKeySet()
	for _, e := range galEls {
		evk.GaloisKeys[e] = keygen.GenGaloisKeyNew(e, secretKey)
	}
	evk.RelinearizationKey = keygen.GenRelinearizationKeyNew(secretKey)

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

func BasicEvaluationKeys(parameters rlwe.Parameters, keygen rlwe.KeyGenerator, key *rlwe.SecretKey) rlwe.EvaluationKeySet {
	galEl := parameters.GaloisElementForColumnRotationBy(-1)
	galEl2 := parameters.GaloisElementForRowRotation()
	galEl3 := parameters.GaloisElementForColumnRotationBy(pasta.T) // useful for MatMulTest
	galEl4 := parameters.GaloisElementForColumnRotationBy(-200)    // useful for Affine test
	galEl5 := parameters.GaloisElementForColumnRotationBy(1)       // useful for Affine test
	els := []uint64{galEl, galEl2, galEl3, galEl4, galEl5}

	for k := 0; k < BsgsN2; k++ {
		els = append(els, parameters.GaloisElementForColumnRotationBy(-k*BsgsN1))
	}

	evk := rlwe.NewEvaluationKeySet()
	for _, e := range els {
		evk.GaloisKeys[e] = keygen.GenGaloisKeyNew(e, key)
	}

	evk.RelinearizationKey = keygen.GenRelinearizationKeyNew(key)

	return *evk
}

func RandomBiases(matrixSize uint64, plainMod uint64) [][]uint64 {
	b := make([][]uint64, pasta.NumMatmulsSquares)
	for r := 0; r < pasta.NumMatmulsSquares; r++ {
		b[r] = make([]uint64, matrixSize)
		for i := uint64(0); i < matrixSize; i++ {
			b[r][i] = rand.Uint64() % plainMod
		}
	}
	return b
}

func RandomMatrices(matrixSize uint64, plainMod uint64) [][][]uint64 {
	m := make([][][]uint64, pasta.NumMatmulsSquares)
	for r := 0; r < pasta.NumMatmulsSquares; r++ {
		m[r] = make([][]uint64, matrixSize)
		for i := uint64(0); i < matrixSize; i++ {
			m[r][i] = make([]uint64, matrixSize)
			for j := 0; uint64(j) < matrixSize; j++ {
				m[r][i][j] = rand.Uint64() % plainMod // not cryptosecure
			}
		}
	}
	return m
}
