package util

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const (
	Add int = iota
	Sub
	Mul
)

type BasicCase struct {
	TestName string
	CaseType int
	El1      []uint64
	El2      []uint64
}

type SerializedCase struct {
	TestName           string `json:"testName"`
	Operation          int    `json:"operation"`
	El1                []byte `json:"el1"`
	El2                []byte `json:"el2"`
	ExpectedResult     []byte `json:"expectedResult"`
	SecretKey          []byte `json:"secretKey"`
	RelinearizationKey []byte `json:"relinearizationKey"`
}

func ExecuteOp(evaluator bfv.Evaluator, ct1 *rlwe.Ciphertext, ct2 *rlwe.Ciphertext, caseType int) *rlwe.Ciphertext {
	var result *rlwe.Ciphertext
	switch caseType {
	case Add:
		fmt.Println("ExecuteOpAdd")
		result = evaluator.AddNew(ct1, ct2)
		break
	case Sub:
		fmt.Println("ExecuteOpSub")
		result = evaluator.SubNew(ct1, ct2)
		break
	case Mul:
		{
			fmt.Println("ExecuteOpMul")
			result = evaluator.MulRelinNew(ct1, ct2)
			break
		}
	default:
		panic("this is unexpected")
	}

	return result
}
