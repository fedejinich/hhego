package bfv

import (
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
	linearTransform := bfv.GenLinearTransform(u.encoder, sliceToMap(mat1), u.bfvParams.MaxLevel(),
		u.bfvParams.DefaultScale())

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

// todo(fedejinich) shouldn't use this, is non performant
func sliceToMap(slice [][]uint64) map[int][]uint64 {
	result := make(map[int][]uint64)

	for idx, subSlice := range slice {
		result[idx] = subSlice
	}

	return result
}
