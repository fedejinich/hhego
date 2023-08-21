package bfv

import (
	"fmt"
	"github.com/fedejinich/hhego/pasta"
	"github.com/fedejinich/hhego/util"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

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
