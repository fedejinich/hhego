package pasta

import "C"
import (
	"encoding/binary"
	"math/big"

	"golang.org/x/crypto/sha3"
)

const PastaT = PlaintextSize // plain text size

type SecretKey []uint64
type Block [PastaT]uint64

type Util struct {
	shake128_ sha3.ShakeHash

	secretKey_       SecretKey
	state1_, state2_ Block

	maxPrimeSize, modulus uint64

	rounds int
}

func NewPastaUtil(secretKey []uint64, modulus uint64, rounds int) Util {
	var state1, state2 [PastaT]uint64
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

func (p *Util) Keystream(nonce uint64, blockCounter uint64) Block {
	p.InitShake(nonce, blockCounter)

	// init state
	for i := 0; i < PastaT; i++ {
		p.state1_[i] = p.secretKey_[i]
		p.state2_[i] = p.secretKey_[PastaT+i]
	}

	for r := 0; r < p.rounds; r++ {
		p.round(r)
	}

	// final affine with mixing afterwards
	p.linearLayer()

	return p.state1_
}

func (p *Util) InitShake(nonce, blockCounter uint64) {
	seed := make([]byte, 16)

	binary.BigEndian.PutUint64(seed[:8], nonce)
	binary.BigEndian.PutUint64(seed[8:], blockCounter)

	shake := sha3.NewShake128()
	if _, err := shake.Write(seed); err != nil {
		panic("SHAKE128 update failed")
	}

	p.shake128_ = shake
}

func (p *Util) RandomMatrix() [][]uint64 {
	mat := make([][]uint64, PastaT)
	mat[0] = p.getRandomVector(false)
	for i := uint64(1); i < PastaT; i++ {
		mat[i] = p.calculateRow(mat[i-1], mat[0]) // todo(fedejinich) this might be changed for calculateColumn
	}
	return mat
}

func (p *Util) RCVec(vecSize uint64) []uint64 {
	rc := make([]uint64, vecSize+PastaT)
	for i := 0; i < PastaT; i++ {
		rc[i] = p.generateRandomFieldElement(false)
	}
	for i := vecSize; i < vecSize+PastaT; i++ {
		rc[i] = p.generateRandomFieldElement(false)
	}
	return rc
}

func (p *Util) getRandomVector(allowZero bool) []uint64 {
	rc := make([]uint64, PastaT)
	for i := uint16(0); i < uint16(PastaT); i++ {
		rc[i] = p.generateRandomFieldElement(allowZero)
	}
	return rc
}

func (p *Util) generateRandomFieldElement(allowZero bool) uint64 {
	var randomBytes [8]byte
	for {
		if _, err := p.shake128_.Read(randomBytes[:]); err != nil {
			panic("SHAKE128 squeeze failed")
		}

		ele := binary.BigEndian.Uint64(randomBytes[:]) & p.maxPrimeSize

		if !allowZero && ele == 0 {
			continue
		}

		if ele < p.modulus {
			return ele
		}
	}
}

// The r-round Pasta construction to generate the keystream KN,i for block i under nonce N with affine layers Aj.
func (p *Util) round(r int) {
	// Ai
	p.linearLayer()

	// S(x) or S'(x)
	if r == int(p.rounds)-1 {
		p.sboxCube(&p.state1_)
		p.sboxCube(&p.state2_)
	} else {
		p.sboxFeistel(&p.state1_)
		p.sboxFeistel(&p.state2_)
	}
}

// Aij(y) = Mij X y + cij
func (p *Util) linearLayer() {
	p.matmul(&p.state1_)
	p.matmul(&p.state2_)

	p.addRc(&p.state1_)
	p.addRc(&p.state2_)

	p.mix()
}

// Mij X y
func (p *Util) matmul(state *Block) {
	var newState Block

	rand := p.getRandomVector(false)
	currRow := rand

	for i := 0; i < PastaT; i++ {
		for j := 0; j < PastaT; j++ {
			mult := new(big.Int).Mul(
				big.NewInt(int64(currRow[j])),
				big.NewInt(int64(state[j])),
			)
			modulus := big.NewInt(int64(p.modulus))
			mult.Mod(mult, modulus)
			newState[i] = (newState[i] + mult.Uint64()) % p.modulus
		}
		if i != PastaT-1 {
			currRow = p.calculateRow(currRow, rand) // todo(fedejinich) if rows are columns, is this ok?
		}
	}
	*state = newState
}

// + cij
func (p *Util) addRc(state *Block) {
	for i := 0; i < PastaT; i++ {
		randomFE := p.generateRandomFieldElement(true)

		currentState := big.NewInt(int64(state[i]))
		randomFEInt := big.NewInt(int64(randomFE))

		modulus := big.NewInt(int64(p.modulus))
		currentState.Add(currentState, randomFEInt)
		currentState.Mod(currentState, modulus)

		state[i] = currentState.Uint64()
	}
}

// [S(x)]i = (x)3
func (p *Util) sboxCube(state *Block) {
	for i := 0; i < PastaT; i++ {
		currentState := big.NewInt(int64(state[i]))
		modulus := big.NewInt(int64(p.modulus))

		square := new(big.Int).Mul(currentState, currentState)
		square.Mod(square, modulus)
		cube := square.Mul(square, currentState)

		state[i] = cube.Mod(cube, modulus).Uint64()
	}
}

// S'(x) = x + (rot(-1)(x) . m)^2
func (p *Util) sboxFeistel(state *Block) {
	pastaP := big.NewInt(int64(p.modulus))
	var newState Block
	newState[0] = state[0]

	for i := 1; i < PastaT; i++ {
		stateBig := big.NewInt(int64(state[i-1]))

		square := new(big.Int).Mul(stateBig, stateBig)
		cube := square.Mod(square, pastaP)
		cubeAdd := cube.Add(cube, big.NewInt(int64(state[i])))
		newElem := cubeAdd.Mod(cubeAdd, pastaP)

		newState[i] = newElem.Uint64()
	}

	*state = newState
}

func (p *Util) calculateRow(prevRow, firstRow []uint64) []uint64 {
	out := make([]uint64, PastaT)

	prevRowLast := big.NewInt(int64(prevRow[PastaT-1]))

	for j := 0; j < PastaT; j++ {
		firstRowVal := big.NewInt(int64(firstRow[j]))

		tmp := new(big.Int).Mul(firstRowVal, prevRowLast)
		modulus := big.NewInt(int64(p.modulus))
		tmp.Mod(tmp, modulus)

		if j > 0 {
			prevRowVal := big.NewInt(int64(prevRow[j-1]))
			tmp.Add(tmp, prevRowVal)
			tmp.Mod(tmp, modulus)
		}

		out[j] = tmp.Uint64()
	}

	return out
}

func (p *Util) mix() {
	for i := 0; i < PastaT; i++ {
		pastaP := big.NewInt(int64(p.modulus))
		state1 := big.NewInt(int64(p.state1_[i]))
		state2 := big.NewInt(int64(p.state2_[i]))

		sum := new(big.Int).Add(state1, state2)
		sum = sum.Mod(sum, pastaP)

		sum1 := new(big.Int).Add(state1, sum)
		sum1 = sum1.Mod(sum1, pastaP)

		sum2 := new(big.Int).Add(state2, sum)
		sum2 = sum2.Mod(sum2, pastaP)

		p.state1_[i] = sum1.Uint64()
		p.state2_[i] = sum2.Uint64()
	}
}
