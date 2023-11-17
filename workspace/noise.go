package main

import (
	"fmt"

	bfv2"github.com/fedejinich/hhego/bfv"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func main() {
	// setup a basic fh scheme
	// do tons of multiplications
	// measure noise
	// it should grow
	bfvParams, _ := bfv.NewParametersFromLiteral(bfv.PN15QP827pq)

	bfvSK, _ := rlwe.NewKeyGenerator(bfvParams.Parameters).
		GenKeyPairNew()
	encryptor := bfv.NewEncryptor(bfvParams, bfvSK)
	decryptor := bfv.NewDecryptor(bfvParams, bfvSK)
	encoder := bfv.NewEncoder(bfvParams)
	evks := rlwe.NewEvaluationKeySet()
	evks.RelinearizationKey = rlwe.NewRelinearizationKey(bfvParams.Parameters)
	evaluator := bfv.NewEvaluator(bfvParams, evks)

	// val := []uint64{2, 3, 3, 4, 2, 3}
	val := []uint64{1, 2, 3}
	pt := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
	encoder.Encode(val, pt)
	ct := encryptor.EncryptNew(pt)

	for i := 0; i < 290; i++ {
		bfv2.NoiseBudget(decryptor, encoder, evaluator, ct)
		// evaluator.MulRelin(ct, ct, ct)
		evaluator.Add(ct, ct, ct)
		fmt.Println(i)

		bfv2.NoiseBudget(decryptor, encoder, evaluator, ct)
	}
}


