package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/fedejinich/hhego/util"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// generates test files
func generateCases() {
	cases := []util.Case{
		{
			TestName: "test_add",
			CaseType: util.Add,
			El1:      []uint64{43, 32},
			El2:      []uint64{12, 23},
		},
		{
			TestName: "test_sub",
			CaseType: util.Sub,
			El1:      []uint64{43, 32},
			El2:      []uint64{12, 23},
		},
		{
			TestName: "test_mul",
			CaseType: util.Mul,
			El1:      []uint64{43, 32},
			El2:      []uint64{12, 23},
		},
	}

	bfvParams, _ := bfv.NewParametersFromLiteral(bfv.PN15QP827pq)

	keyGenerator := bfv.NewKeyGenerator(bfvParams)
	secretKey, _ := keyGenerator.GenKeyPairNew()

	encryptor := bfv.NewEncryptor(bfvParams, secretKey)

	evk := rlwe.NewEvaluationKeySet()
	evk.RelinearizationKey = keyGenerator.GenRelinearizationKeyNew(secretKey)
	evaluator := bfv.NewEvaluator(bfvParams, evk)
	encoder := bfv.NewEncoder(bfvParams)

	// generate serialized cases
	serializedCases := make([]util.SerializedCase, len(cases))
	for i, c := range cases {
		pt1 := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())
		pt2 := bfv.NewPlaintext(bfvParams, bfvParams.MaxLevel())

		encoder.Encode(c.El1, pt1)
		encoder.Encode(c.El1, pt2)

		ct1 := encryptor.EncryptNew(pt1)
		ct2 := encryptor.EncryptNew(pt2)

		expectedResult := util.ExecuteOp(evaluator, ct1, ct2, c.CaseType)

		serializedCases[i] = newCase(c.TestName, c.CaseType, ct1, ct2,
			expectedResult, secretKey, evk.RelinearizationKey)
	}

	// write as .json
	fmt.Println(len(serializedCases))
	for _, c := range serializedCases {
		// Write to a file
		err := ioutil.WriteFile(testName(c.TestName), toJSON(c), 0644)
		if err != nil {
			panic("couldn't write to file")
		}
	}

	// Write to a file
	// err := ioutil.WriteFile("output.json", toJSON(serializedCases), 0644)
	// if err != nil {
	// 	panic("couldn't write to file")
	// }
}

func newCase(testName string, caseType int, el1 *rlwe.Ciphertext, el2 *rlwe.Ciphertext, expectedResult *rlwe.Ciphertext, key *rlwe.SecretKey, relinearizationKey *rlwe.RelinearizationKey) util.SerializedCase {

	e1, _ := el1.MarshalBinary()
	e2, _ := el2.MarshalBinary()
	eR, _ := expectedResult.MarshalBinary()

	sk, _ := key.MarshalBinary()
	rk, _ := relinearizationKey.MarshalBinary()

	return util.SerializedCase{
		TestName:           testName,
		Operation:          caseType,
		El1:                e1,
		El2:                e2,
		ExpectedResult:     eR,
		SecretKey:          sk,
		RelinearizationKey: rk,
	}
}

func toJSON(c util.SerializedCase) []byte {
	jsonData, err := json.Marshal(c)
	if err != nil {
		panic("wrong json produced")
	}
	return jsonData
}

func testName(name string) string {
	fmt.Println(name)
	return fmt.Sprintf("%s.json", name)
}

func main() { generateCases() }
