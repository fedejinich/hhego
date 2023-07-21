package main

import (
	"encoding/json"
	"github.com/fedejinich/hhego/util"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"io/ioutil"
)

// generates test files
func generateCases() {
	cases := []util.Case{
		{
			CaseType: util.Add,
			El1:      []uint64{43, 32},
			El2:      []uint64{12, 23},
		},
		{
			CaseType: util.Sub,
			El1:      []uint64{43, 32},
			El2:      []uint64{12, 23},
		},
		{
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

		var expectedResult *rlwe.Ciphertext
		switch c.CaseType {
		case util.Add:
			expectedResult = evaluator.AddNew(ct1, ct2)
			break
		case util.Sub:
			expectedResult = evaluator.SubNew(ct1, ct2)
			break
		case util.Mul:
			{
				r := evaluator.MulNew(ct1, ct2)
				// todo(fedejinich) this might be optional
				expectedResult = evaluator.RelinearizeNew(r)
				break
			}
		default:
			panic("this is unexpected")
		}

		serializedCases[i] = newCase(c.CaseType, ct1, ct2, expectedResult)
	}

	// Write to a file
	err := ioutil.WriteFile("output.json", toJSON(serializedCases), 0644)
	if err != nil {
		panic("couldn't write to file")
	}
}

func newCase(caseType int, el1 *rlwe.Ciphertext, el2 *rlwe.Ciphertext, expectedResult *rlwe.Ciphertext) util.SerializedCase {
	e1, _ := el1.MarshalBinary()
	e2, _ := el2.MarshalBinary()
	eR, _ := expectedResult.MarshalBinary()

	return util.SerializedCase{
		Operation:      caseType,
		El1:            e1,
		El2:            e2,
		ExpectedResult: eR,
	}
}

func toJSON(c []util.SerializedCase) []byte {
	jsonData, err := json.Marshal(c)
	if err != nil {
		panic("wrong json produced")
	}
	return jsonData
}

func main() { generateCases() }
