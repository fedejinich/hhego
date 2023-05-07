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

func (u *Util) AddRc(state *rlwe.Ciphertext, rc []uint64) *rlwe.Ciphertext {
	roundConstants := bfv.NewPlaintext(u.bfvParams, state.Level())
	u.encoder.Encode(rc, roundConstants)
	return u.evaluator.AddNew(state, roundConstants) // ct + pt
}

func (u *Util) Mix(state *rlwe.Ciphertext) *rlwe.Ciphertext {
	stateOriginal := state.CopyNew()
	tmp := u.evaluator.RotateRowsNew(state)
	tmp = u.evaluator.AddNew(tmp, stateOriginal)
	return u.evaluator.AddNew(stateOriginal, tmp)
}

func (u *Util) SboxCube(state *rlwe.Ciphertext) *rlwe.Ciphertext {
	s := state.CopyNew()
	state = u.evaluator.MulNew(state, state) // ^ 2 ct x ct -> relinearization
	state = u.evaluator.RelinearizeNew(state)
	state = u.evaluator.MulNew(state, s) // ^ 3  ct x ct -> relinearization
	state = u.evaluator.RelinearizeNew(state)
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
	stateRot = u.evaluator.MulNew(stateRot, mask) // ct x pt

	// square
	state = u.evaluator.MulNew(stateRot, stateRot)
	state = u.evaluator.RelinearizeNew(state) // ct x ct -> relinearization

	// add
	result := u.evaluator.AddNew(originalState, state)

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

func (u *Util) Reminder(matrixSize uint64, plainSize uint64) uint64 {
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
