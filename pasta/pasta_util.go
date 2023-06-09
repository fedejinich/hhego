package pasta

import "C"
import (
	"encoding/binary"
	"math/big"

	"golang.org/x/crypto/sha3"
)

const T = PlaintextSize // plain text size

type SecretKey []uint64
type Block [T]uint64

type Util struct {
	shake128_ sha3.ShakeHash

	secretKey_       SecretKey // todo(fedejinich) remove this field, it's unnecesary, only needed for Keystream. Provide it as a param
	state1_, state2_ Block

	maxPrimeSize, modulus uint64

	rounds int
}

func NewUtil(secretKey []uint64, modulus uint64, rounds int) Util {
	var state1, state2 [T]uint64
	p := modulus

	maxPrimeSize := uint64(0)
	for p > 0 {
		maxPrimeSize++
		p >>= 1
	}
	maxPrimeSize = (1 << maxPrimeSize) - 1

	return Util{
		nil,
		secretKey,
		state1,
		state2,
		maxPrimeSize,
		modulus,
		rounds,
	}
}

func (u *Util) Keystream(nonce uint64, blockCounter uint64) Block {
	u.InitShake(nonce, blockCounter)

	// init state
	for i := 0; i < T; i++ {
		u.state1_[i] = u.secretKey_[i]
		u.state2_[i] = u.secretKey_[T+i]
	}

	for r := 0; r < u.rounds; r++ {
		u.round(r)
	}

	// final affine with mixing afterwards
	u.linearLayer()

	return u.state1_
}

func (u *Util) InitShake(nonce, blockCounter uint64) {
	seed := make([]byte, 16)

	binary.BigEndian.PutUint64(seed[:8], nonce)
	binary.BigEndian.PutUint64(seed[8:], blockCounter)

	shake := sha3.NewShake128()
	if _, err := shake.Write(seed); err != nil {
		panic("SHAKE128 update failed")
	}

	u.shake128_ = shake
}

func (u *Util) RandomMatrix() [][]uint64 {
	return u.RandomMatrixBy(u.GetRandomVector(false))
}

func (u *Util) RandomMatrixBy(vec []uint64) [][]uint64 {
	mat := make([][]uint64, T)
	mat[0] = vec
	for i := uint64(1); i < T; i++ {
		mat[i] = u.calculateRow(mat[i-1], mat[0])
	}
	return mat
}

func (u *Util) RCVec(vecSize uint64) []uint64 {
	rc := make([]uint64, vecSize+T)
	for i := uint64(0); i < vecSize+T; i++ {
		rc[i] = 0
	}

	for i := 0; i < T; i++ {
		rc[i] = u.GenerateRandomFieldElement(true)
	}
	for i := vecSize; i < vecSize+T; i++ {
		rc[i] = u.GenerateRandomFieldElement(true)
	}
	return rc
}

func (u *Util) GetRandomVector(allowZero bool) []uint64 {
	rc := make([]uint64, T)
	for i := uint16(0); i < uint16(T); i++ {
		rc[i] = u.GenerateRandomFieldElement(allowZero)
	}
	return rc
}

func (u *Util) GenerateRandomFieldElement(allowZero bool) uint64 {
	var randomBytes [8]byte
	for {
		if _, err := u.shake128_.Read(randomBytes[:]); err != nil {
			panic("SHAKE128 squeeze failed")
		}

		ele := binary.BigEndian.Uint64(randomBytes[:]) & u.maxPrimeSize

		if !allowZero && ele == 0 {
			continue
		}

		if ele < u.modulus {
			return ele
		}
	}
}

// The r-round Pasta construction to generate the keystream KN,i for block i under nonce N with affine layers Aj.
func (u *Util) round(r int) {
	// Ai
	u.linearLayer()

	// S(x) or S'(x)
	if r == int(u.rounds)-1 {
		u.SboxCube(&u.state1_)
		u.SboxCube(&u.state2_)
	} else {
		u.SboxFeistel(&u.state1_)
		u.SboxFeistel(&u.state2_)
	}
}

// Aij(y) =
// |2I I|
// |I 2I| X [Mij X y + cij]
func (u *Util) linearLayer() {
	u.Matmul(&u.state1_)
	u.Matmul(&u.state2_)

	u.AddRc(&u.state1_)
	u.AddRc(&u.state2_)

	u.Mix()
}

func (u *Util) Matmul(state *Block) {
	u.MatmulBy(state, u.GetRandomVector(false))
}

// Mij X y
func (u *Util) MatmulBy(state *Block, vec []uint64) {
	var newState Block

	rand := vec
	currRow := rand

	for i := 0; i < T; i++ {
		for j := 0; j < T; j++ {
			mult := new(big.Int).Mul(
				big.NewInt(int64(currRow[j])),
				big.NewInt(int64(state[j])),
			)
			modulus := big.NewInt(int64(u.modulus))
			mult.Mod(mult, modulus)
			newState[i] = (newState[i] + mult.Uint64()) % u.modulus
		}
		if i != T-1 {
			currRow = u.calculateRow(currRow, rand)
		}
	}
	*state = newState
}

// + cij
func (u *Util) AddRc(state *Block) {
	rcVec := u.GetRandomVector(true)
	u.AddRcBy(state, rcVec)
}

// this is only exposed for testing
func (u *Util) AddRcBy(state *Block, randomFEVec []uint64) {
	for i := 0; i < T; i++ {
		currentState := big.NewInt(int64(state[i]))
		randomFEInt := big.NewInt(int64(randomFEVec[i]))

		modulus := big.NewInt(int64(u.modulus))
		currentState.Add(currentState, randomFEInt)
		currentState.Mod(currentState, modulus)

		state[i] = currentState.Uint64()
	}
}

// [S(x)]i = (x)3
func (u *Util) SboxCube(state *Block) {
	for i := 0; i < T; i++ {
		currentState := big.NewInt(int64(state[i]))
		modulus := big.NewInt(int64(u.modulus))

		square := new(big.Int).Mul(currentState, currentState)
		square.Mod(square, modulus)
		cube := square.Mul(square, currentState)

		state[i] = cube.Mod(cube, modulus).Uint64()
	}
}

// S'(x) = x + (rot(-1)(x) . m)^2
func (u *Util) SboxFeistel(state *Block) {
	pastaP := big.NewInt(int64(u.modulus))
	var newState Block
	newState[0] = state[0]

	for i := 1; i < T; i++ {
		stateBig := big.NewInt(int64(state[i-1]))

		square := new(big.Int).Mul(stateBig, stateBig)
		cube := square.Mod(square, pastaP)
		cubeAdd := cube.Add(cube, big.NewInt(int64(state[i])))
		newElem := cubeAdd.Mod(cubeAdd, pastaP)

		newState[i] = newElem.Uint64()
	}

	*state = newState
}

func (u *Util) calculateRow(prevRow, firstRow []uint64) []uint64 {
	out := make([]uint64, T)

	//prevRowLast := big.NewInt(int64(prevRow[T-1]))
	modulus := big.NewInt(int64(u.modulus))

	for j := 0; j < T; j++ {
		firstRowBig := big.NewInt(int64(firstRow[j]))
		tmpBig := big.NewInt(int64(prevRow[T-1]))
		tmp := new(big.Int).Mul(firstRowBig, tmpBig)
		tmp = tmp.Mod(tmp, modulus)

		if j > 0 {
			tmp = tmp.Add(tmp, big.NewInt(int64(prevRow[j-1])))
			tmp = tmp.Mod(tmp, modulus)
		}

		out[j] = tmp.Uint64()
	}

	return out
}

// this is an optimized implementation of
// (2 1)(state1_)
// (1 2)(state2_)
func (u *Util) Mix() {
	for i := 0; i < T; i++ {
		pastaP := big.NewInt(int64(u.modulus))
		state1 := big.NewInt(int64(u.state1_[i]))
		state2 := big.NewInt(int64(u.state2_[i]))

		sum := new(big.Int).Add(state1, state2)
		sum = sum.Mod(sum, pastaP)

		sum1 := new(big.Int).Add(state1, sum)
		sum1 = sum1.Mod(sum1, pastaP)

		sum2 := new(big.Int).Add(state2, sum)
		sum2 = sum2.Mod(sum2, pastaP)

		u.state1_[i] = sum1.Uint64()
		u.state2_[i] = sum2.Uint64()
	}
}

// this is an optimized implementation of
// (2 1)(state1_)
// (1 2)(state2_)
func (u *Util) MixBy(s1, s2 *Block) {
	u.state1_ = *s1
	u.state2_ = *s2
	u.Mix()
}

// todo(fedejinich) only used for testing
func (u *Util) State() *Block {
	return &u.state1_
}
