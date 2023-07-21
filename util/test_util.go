package util

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const (
	Add int = iota
	Sub
	Mul
)

type Case struct {
	CaseType int
	El1      []uint64
	El2      []uint64
}

type SerializedCase struct {
	Operation      int    `json:"operation"`
	El1            []byte `json:"el1"`
	El2            []byte `json:"el2"`
	ExpectedResult []byte `json:"expectedResult"`
}

func ExecuteOp(evaluator bfv.Evaluator, ct1 *rlwe.Ciphertext, ct2 *rlwe.Ciphertext, caseType int) *rlwe.Ciphertext {
	var result *rlwe.Ciphertext
	switch caseType {
	case Add:
		result = evaluator.AddNew(ct1, ct2)
		break
	case Sub:
		result = evaluator.SubNew(ct1, ct2)
		break
	case Mul:
		{
			r := evaluator.MulNew(ct1, ct2)
			// todo(fedejinich) this might be optional
			result = evaluator.RelinearizeNew(r)
			break
		}
	default:
		panic("this is unexpected")
	}

	return result
}
