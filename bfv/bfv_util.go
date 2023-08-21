package bfv

import (
	"fmt"
	"github.com/fedejinich/hhego/pasta"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math"
	"math/rand"
	"time"
)

// BsgsN1 used for babystep-gigantstep
const BsgsN1 = 16

// BsgsN2 used for babystep-gigantstep
const BsgsN2 = 8

func GenerateBfvParams(modulus uint64, degree uint64) bfv.Parameters {
	var bfvParams bfv.ParametersLiteral
	if degree == uint64(math.Pow(2, 14)) {
		fmt.Println("polynomial modDegree (LogN) = 2^14 (16384)")
		bfvParams = bfv.PN14QP411pq // post-quantum params
	} else if degree == uint64(math.Pow(2, 15)) {
		fmt.Println("polynomial modDegree (LogN) = 2^15 (32768)")
		bfvParams = bfv.PN15QP827pq // post-quantum params
	} else if degree == uint64(math.Pow(2, 16)) {
		fmt.Println("polynomial modDegree (LogN) = 2^16 (65536)")
		bfvParams = bfv.ParametersLiteral{
			LogN: 16,
			T:    0xffffffffffc0001,
			Q: []uint64{0x10000000006e0001,
				0xfffffffff840001,
				0x1000000000860001,
				0xfffffffff6a0001,
				0x1000000000980001,
				0xfffffffff5a0001,
				0x1000000000b00001,
				0x1000000000ce0001,
				0xfffffffff2a0001,
				0xfffffffff240001,
				0x1000000000f00001,
				0xffffffffefe0001,
				0x10000000011a0001,
				0xffffffffeca0001,
				0xffffffffe9e0001,
				0xffffffffe7c0001,
				0xffffffffe740001,
				0x10000000019a0001,
				0x1000000001a00001,
				0xffffffffe520001,
				0xffffffffe4c0001,
				0xffffffffe440001,
				0x1000000001be0001,
				0xffffffffe400001},
			P: []uint64{0x1fffffffffe00001,
				0x1fffffffffc80001,
				0x2000000000460001,
				0x1fffffffffb40001,
				0x2000000000500001},
		}
	} else {
		panic(fmt.Sprintf("polynomial modDegree not supported (modDegree)"))
	}

	fmt.Println(fmt.Sprintf("modulus (T) = %d", modulus))
	bfvParams.T = modulus

	params, err := bfv.NewParametersFromLiteral(bfvParams)
	if err != nil {
		panic(fmt.Sprintf("couldn't initialize bfvParams"))
	}

	return params
}

func RandomInputV(N int, plainMod uint64) []uint64 {
	rand.Seed(time.Now().UnixNano())
	vi := make([]uint64, 0, N)
	for i := 0; i < N; i++ {
		vi = append(vi, rand.Uint64()%plainMod) // not cryptosecure ;)
	}
	return vi
}

func GenEvks(params rlwe.Parameters, galEls []uint64, secretKey *rlwe.SecretKey, rk *rlwe.RelinearizationKey) *rlwe.EvaluationKeySet {
	keygen := rlwe.NewKeyGenerator(params)
	evk := rlwe.NewEvaluationKeySet()

	// set create galois keys (for rotations)
	for _, e := range galEls {
		evk.GaloisKeys[e] = keygen.GenGaloisKeyNew(e, secretKey)
	}

	// set relineraization key (for mul)
	evk.RelinearizationKey = rk

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

func addDiagonalIndices(messageLength uint64, gkIndices *[]int, slots uint64) {
	if messageLength*2 != slots {
		*gkIndices = append(*gkIndices, -int(messageLength))
	}
	*gkIndices = append(*gkIndices, 1)
}

func BasicEvaluationKeys(parameters rlwe.Parameters, keygen rlwe.KeyGenerator, sk *rlwe.SecretKey) rlwe.EvaluationKeySet {
	galEl := parameters.GaloisElementForColumnRotationBy(-1)
	galEl2 := parameters.GaloisElementForRowRotation()
	galEl3 := parameters.GaloisElementForColumnRotationBy(pasta.T) // useful for MatMulTest
	galEl4 := parameters.GaloisElementForColumnRotationBy(-200)    // useful for Affine test
	galEl5 := parameters.GaloisElementForColumnRotationBy(1)       // useful for Affine test
	galEls := []uint64{galEl, galEl2, galEl3, galEl4, galEl5}

	for k := 0; k < BsgsN2; k++ {
		galEls = append(galEls, parameters.GaloisElementForColumnRotationBy(-k*BsgsN1))
	}

	return *GenEvks(parameters, galEls, sk, keygen.GenRelinearizationKeyNew(sk))
}
