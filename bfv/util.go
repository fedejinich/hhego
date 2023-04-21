package bfv

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	util "hhego"
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

func (u *Util) AddRc(state *rlwe.Ciphertext, rc []uint64) *rlwe.Ciphertext {
	roundConstants := bfv.NewPlaintext(u.bfvParams, u.bfvParams.MaxLevel())
	u.encoder.Encode(rc, roundConstants)
	return u.evaluator.AddNew(state, roundConstants)
}

func (u *Util) Mix(state *rlwe.Ciphertext) *rlwe.Ciphertext {
	tmp := u.evaluator.RotateRowsNew(state) // todo(fedejinich) this is called 'rotate_columns' in SEAL
	u.evaluator.Add(tmp, state, state)
	return u.evaluator.AddNew(state, tmp)
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
	// rotate state
	stateRot := u.evaluator.RotateColumnsNew(state, -1) // todo(fedejinich) this is called 'rotate_rows' in SEAL

	// mask rotate state
	mask := bfv.NewPlaintext(u.bfvParams, u.bfvParams.MaxLevel()) // todo(fedejinich) not sure about 'Level'
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
	u.evaluator.Mul(stateRot, mask, stateRot) // no need to relinearize because it's been multiplied by a plain
	// stateRot = 0, x_1, x_2, x_3, .... x_(t-1)

	// square
	u.evaluator.Mul(stateRot, stateRot, stateRot)
	u.evaluator.Relinearize(stateRot, stateRot) // needs relinearization
	// stateRot = 0, x_1^2, x_2^2, x_3^2, .... x_(t-1)^2

	result := u.evaluator.AddNew(state, stateRot)
	// state = x_1, x_1^2 + x_2, x_2^2 + x_3, x_3^2 + x_4, .... x_(t-1)^2 + x_t

	return result
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

func (u Util) Matmul2(state *rlwe.Ciphertext, mat1, mat2 [][]uint64, slots, halfslots uint64) *rlwe.Ciphertext {
	return u.babyStepGigantStep(state, mat1, mat2, slots, halfslots)
}

// todo(fedejinich) this constants shouldn't be here
const BsgsN1 = 16
const BsgsN2 = 8

func (u *Util) babyStepGigantStep(state *rlwe.Ciphertext, mat1 [][]uint64, mat2 [][]uint64, slots, halfslots uint64) *rlwe.Ciphertext {
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
		diagSize := int(halfslots) + matrixDim
		diag := make([]uint64, diagSize)
		tmpSize := matrixDim
		tmp := make([]uint64, tmpSize)

		k := uint64(i / BsgsN1)

		for j := 0; j < matrixDim; j++ {
			diag[diagSize-1-j] = mat1[j][(j+matrixDim-i)%matrixDim] // push back
			tmp[tmpSize-1-j] = mat2[j][(j+matrixDim-i)%matrixDim]   // push back
		}

		// rotate:
		if k != 0 {
			util.Rotate(diag[0], diag[0]+(uint64(k)*BsgsN1), diag[len(diag)-1], diag) // todo(fedejinich) not sure about using this method
			util.Rotate(tmp[0], tmp[0]+(uint64(k)*BsgsN1), tmp[len(tmp)-1], tmp)      // todo(fedejinich) not sure about using this method
		}

		// prepare for non-full-packed rotations
		if halfslots != pasta.T {
			newSize := int(halfslots)
			diag = resize(diag, newSize, 0) // todo(fedejinich) resize uses append
			tmp = resize(tmp, newSize, 0)   // todo(fedejinich) resize uses append
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
		diag = resize(diag, int(slots), 0) // todo(fedejinich) resize uses append
		for j := halfslots; j < slots; j++ {
			diag[j] = tmp[j-halfslots]
		}

		r := bfv.NewPlaintext(u.bfvParams, u.bfvParams.MaxLevel())
		u.encoder.Encode(diag, r)
		matrix[matrixDim-i-1] = *r // push back
	}

	// prepare for non-full-packed rotations
	if halfslots != pasta.T {
		s := state.CopyNew()
		stateRot := u.evaluator.RotateColumnsNew(s, pasta.T)
		state = u.evaluator.AddNew(state, stateRot)
	}

	// prepare rotations
	rot := make([]rlwe.Ciphertext, BsgsN1)
	rot[0] = *state
	for j := 1; j < BsgsN1; j++ {
		rot[j] = *u.evaluator.RotateColumnsNew(&rot[j-1], -1)
	}

	var outerSum rlwe.Ciphertext
	for k := 0; k < BsgsN2; k++ {
		innerSum := u.evaluator.MulNew(&rot[0], &matrix[k*BsgsN1]) // no needs relinearization
		for j := 1; j < BsgsN1; j++ {
			temp := u.evaluator.MulNew(&rot[j], &matrix[k*BsgsN1+j]) // no needs relinearization
			u.evaluator.Add(innerSum, temp, innerSum)                // todo(fedejinich) not sure about adding an empty 'temp'
		}
		if k != 0 { // todo(fedejinich) not sure about 'k'
			outerSum = *innerSum
		} else {
			if outerSum.Value == nil { // todo(fedejinich) this is not ideal
				outerSum = *rlwe.NewCiphertext(u.bfvParams.Parameters, innerSum.Degree(), innerSum.Level())
			}
			u.evaluator.RotateColumns(innerSum, -k*BsgsN1, innerSum)
			outerSum = *u.evaluator.AddNew(&outerSum, innerSum)
		}
	}

	return &outerSum
}

// todo(fedejinich) shouldn't use this, is non performant
func sliceToMap(slice [][]uint64) map[int][]uint64 {
	result := make(map[int][]uint64)

	for idx, subSlice := range slice {
		result[idx] = subSlice
	}

	return result
}

func resize(slice []uint64, newSize int, value uint64) []uint64 {
	initSize := len(slice)
	if initSize >= newSize {
		return slice[:newSize]
	}

	newSlice := make([]uint64, newSize)
	for i := 0; i < newSize; i++ {
		if i < initSize {
			newSlice[i] = slice[i]
		} else {
			newSlice[i] = value
		}
	}

	return newSlice
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
	plaintext := bfv.NewPlaintext(params, params.MaxLevel()) // halfslots
	encoder.Encode(mask, plaintext)

	evaluator.Mul(&last, plaintext, &last) // no needs relinearization

	decomp[lastIndex] = last // todo(fedejinich) isn't this unnecessary?

	return decomp
}
