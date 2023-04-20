package bfv

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"hhego/pasta"
)

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

func (u *Util) AddRc(state *rlwe.Ciphertext, rc []uint64) {
	roundConstants := bfv.NewPlaintext(u.bfvParams, u.bfvParams.MaxLevel()) // todo(fedejinich) not sure about MaxLevel
	u.encoder.Encode(rc, roundConstants)
	u.evaluator.Add(state, roundConstants, state)
}

func (u *Util) Mix(state *rlwe.Ciphertext) {
	tmp := u.evaluator.RotateRowsNew(state) // todo(fedejinich) this is called 'rotate_columns' in SEAL
	u.evaluator.Add(tmp, state, state)
	u.evaluator.Add(state, tmp, state)
}

func (u *Util) SboxCube(state *rlwe.Ciphertext) {
	for i := 0; i < 3; i++ {
		u.evaluator.Mul(state, state, state)
	}
}

func (u *Util) SboxFeistel(state *rlwe.Ciphertext, halfslots uint64) {
	// rotate state
	stateRot := u.evaluator.RotateColumnsNew(state, -1) // todo(fedejinich) this is called 'rotate_rows' in SEAL

	// mask rotate state
	mask := bfv.NewPlaintext(u.bfvParams, state.Level()) // todo(fedejinich) not sure about 'Level'
	maskVec := make([]uint64, pasta.T+halfslots)
	for i := range maskVec {
		maskVec[i] = 1 // todo(fedejinich) is this ok?
	}
	maskVec[0] = 0
	maskVec[halfslots] = 0
	for i := uint64(pasta.T); i < halfslots; i++ {
		maskVec[i] = 0
	}
	u.encoder.Encode(maskVec, mask)
	u.evaluator.Mul(stateRot, mask, stateRot)
	// stateRot = 0, x_1, x_2, x_3, .... x_(t-1)

	// square
	u.evaluator.Mul(stateRot, stateRot, stateRot)
	u.evaluator.Relinearize(stateRot, stateRot)
	// stateRot = 0, x_1^2, x_2^2, x_3^2, .... x_(t-1)^2

	u.evaluator.Add(state, stateRot, state)
	// state = x_1, x_1^2 + x_2, x_2^2 + x_3, x_3^2 + x_4, .... x_(t-1)^2 + x_t
}

func (u *Util) Matmul(state *rlwe.Ciphertext, mat1 [][]uint64, stateOut **rlwe.Ciphertext) {
	// todo(fedejinich) not sure about maxLevel and DefaultScale
	linearTransform := bfv.GenLinearTransformBSGS(u.encoder, sliceToMap(mat1), u.bfvParams.MaxLevel(),
		u.bfvParams.DefaultScale(), 2.0)

	rotations := linearTransform.Rotations()

	evk := rlwe.NewEvaluationKeySet()
	// todo(fedejinich) this is slow
	for _, galEl := range u.bfvParams.GaloisElementsForRotations(rotations) {
		evk.GaloisKeys[galEl] = u.keygen.GenGaloisKeyNew(galEl, &u.secretKey)
	}

	tmp := u.evaluator.
		WithKey(evk).
		LinearTransformNew(state, linearTransform)

	*stateOut = tmp[0]
}

func (u Util) Matmul2(state *rlwe.Ciphertext, mat1, mat2 [][]uint64, slots, halfslots uint64, stateOut **rlwe.Ciphertext) {
	result := u.babyStepGigantStep(*state, mat1, mat2, slots, halfslots)
	*stateOut = &result
}

// todo(fedejinich) this constants shouldn't be here
const BsgsN1 = 16
const BsgsN2 = 8

func (u *Util) babyStepGigantStep(state rlwe.Ciphertext, mat1 [][]uint64, mat2 [][]uint64, slots, halfslots uint64) rlwe.Ciphertext {
	matrixDim := pasta.T

	if ((matrixDim * 2) != int(slots)) && ((matrixDim * 4) > int(halfslots)) {
		fmt.Println("too little slots for matmul implementation!")
	}

	if BsgsN1*BsgsN2 != matrixDim {
		fmt.Println("wrong bsgs params")
	}

	// diagonal method preperation:
	matrix := make([]rlwe.Plaintext, matrixDim)
	for i := 0; i < matrixDim; i++ {
		diag := make([]uint64, halfslots+uint64(matrixDim))
		tmp := make([]uint64, matrixDim)
		k := uint64(i / BsgsN1)

		for j := 0; j < matrixDim; j++ {
			diag = append(diag, mat1[j][(j+matrixDim-i)%matrixDim])
			tmp = append(tmp, mat2[j][(j+matrixDim-i)%matrixDim])
		}

		// rotate:
		if k != 0 {
			diag = rotate2(diag[0], diag[0]+(k*BsgsN1), diag[len(diag)-1], diag) // todo(fedejinich) not sure about using this method
			tmp = rotate2(tmp[0], tmp[0]+k*BsgsN1, tmp[len(diag)-1], tmp)        // todo(fedejinich) not sure about using this method
		}

		// prepare for non-full-packed rotations
		if halfslots != pasta.T {
			diag = resize(diag, int(halfslots), 0)
			tmp = resize(tmp, int(halfslots), 0)
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
		diag = resize(diag, int(slots), 0)
		for j := halfslots; j < slots; j++ {
			diag[j] = tmp[j-halfslots]
		}

		r := bfv.NewPlaintext(u.bfvParams, u.bfvParams.MaxLevel()) // todo(fedejinich) not sure about max level
		u.encoder.Encode(diag, r)
		matrix = append(matrix, *r)
	}

	// prepare for non-full-packed rotations
	if halfslots != pasta.T {
		s := state.CopyNew()
		stateRot := u.evaluator.RotateColumnsNew(s, pasta.T)
		u.evaluator.Add(&state, stateRot, &state)
	}

	var temp, outerSum, innerSum rlwe.Ciphertext

	// prepare rotations
	rot := make([]rlwe.Ciphertext, BsgsN1)
	rot[0] = state
	for j := 1; j < BsgsN1; j++ {
		u.evaluator.RotateColumns(&rot[j-1], -1, &rot[j])
	}

	for k := 0; k < BsgsN2; k++ {
		u.evaluator.Mul(&rot[0], matrix[k*BsgsN1], &innerSum)
		for j := 1; j < BsgsN1; j++ {
			u.evaluator.Mul(&rot[j], matrix[k*BsgsN1+j], &temp)
			u.evaluator.Add(&innerSum, temp, &innerSum) // todo(fedejinich) not sure about adding an empty 'temp'
		}
		if k != 0 { // todo(fedejinich) not sure about 'k'
			outerSum = innerSum
		} else {
			u.evaluator.RotateColumns(&innerSum, -k*BsgsN1, &innerSum)
			u.evaluator.Add(&outerSum, innerSum, &outerSum)
		}
	}
	return outerSum
}

// todo(fedejinich) review this implementation, it might be wrong
// Performs a left rotation on a range of elements.
// Specifically, std::rotate swaps the elements in the range [first, last)
// in such a way that the elements in [first, middle) are placed after the elements in [middle, last)
// while the orders of the elements in both ranges are preserved.
func rotate(first, middle, last uint64, arr []uint64) uint64 {
	if first == middle {
		return last
	}

	if middle == last {
		return first
	}

	write := first
	nextRead := first

	for read := middle; read != last; write, read = write+1, read+1 {
		if write == nextRead {
			nextRead = read
		}
		arr[write], arr[read] = arr[read], arr[write]
	}

	return rotate(write, nextRead, last, arr)
}

func rotate2(first, middle, last uint64, arr []uint64) []uint64 {
	if first == middle {
		return arr
	}

	if middle == last {
		return arr
	}

	rotated := make([]uint64, len(arr))
	copy(rotated, arr)

	write := first
	nextRead := first

	for read := middle; read != last; write, read = write+1, read+1 {
		if write == nextRead {
			nextRead = read
		}
		rotated[write], rotated[read] = arr[read], arr[write]
	}

	rotated = rotate2(write, nextRead, last, rotated)
	return rotated
}

// it avoids recursion, this might be better
//func rotate(first, middle, last int, arr []int) int {
//	if first == middle {
//		return last
//	}
//
//	if middle == last {
//		return first
//	}
//
//	next := middle
//	for first != next {
//		arr[first], arr[next] = arr[next], arr[first]
//		first++
//		next++
//		if next == last {
//			next = middle
//		} else if first == middle {
//			middle = next
//		}
//	}
//
//	return first
//}

// todo(fedejinich) same considerations as 'rotate'
func resize(slice []uint64, newSize int, value uint64) []uint64 {
	if newSize < 0 || newSize == len(slice) {
		return slice
	}

	if len(slice) < newSize {
		// Grow the slice
		for i := len(slice); i < newSize; i++ {
			slice = append(slice, value)
		}
	} else {
		// Shrink the slice
		slice = slice[:newSize]
	}

	if len(slice) != newSize {
		fmt.Println("wrong resize")
	}

	return slice
}

func (u *Util) Flatten(decomp []rlwe.Ciphertext, plainSize int, evaluator bfv.Evaluator) rlwe.Ciphertext {
	// todo(fedejinich) implement this
	ciphertext := decomp[0]
	for i := 1; i < len(decomp); i++ {
		tmp := evaluator.RotateColumnsNew(&decomp[i], -(i * plainSize))
		evaluator.Add(&ciphertext, tmp, &ciphertext)
	}

	return ciphertext
}

func (u *Util) Mask(decomp []rlwe.Ciphertext, mask []uint64, params bfv.Parameters, encoder bfv.Encoder, evaluator bfv.Evaluator) []rlwe.Ciphertext {
	lastIndex := len(decomp) - 1
	last := decomp[lastIndex]
	plaintext := bfv.NewPlaintext(params, params.MaxLevel()) // todo(fedejinich) not sure about MaxLevel
	encoder.Encode(mask, plaintext)

	evaluator.Mul(&last, plaintext, &last)

	decomp[lastIndex] = last // todo(fedejinich) isn't this unnecessary?

	return decomp
}

// todo(fedejinich) shouldn't use this, is non performant
func sliceToMap(slice [][]uint64) map[int][]uint64 {
	result := make(map[int][]uint64)

	for idx, subSlice := range slice {
		result[idx] = subSlice
	}

	return result
}
